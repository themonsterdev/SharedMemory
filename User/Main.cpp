#include <Windows.h>
#include <aclapi.h>
#include <iostream>

// Shared Memory
// https://github.com/fengjixuchui/SharedMemory-By-Frankoo/tree/master
// https://github.com/IAmTapped/Rust-Cheat-Shared-Memory-Driver/tree/main

using namespace std;

typedef struct _KM_DRIVER_COMMAND {
	UINT8		code;

	// Memory
	PVOID		buffer;
	ULONG64		address;
	ULONG		size;

	// Process
	CHAR processName[32];
	HANDLE processId;
}KM_DRIVER_COMMAND, * PKM_DRIVER_COMMAND;

// shared memory mapping
HANDLE hMapFileW = NULL;

HANDLE GetProcessId(PKM_DRIVER_COMMAND pCommand, const char* processName)
{
	pCommand->code = 1;
	pCommand->processId = NULL;
	strcpy_s(pCommand->processName, processName);
	RtlCopyMemory(pCommand, pCommand, sizeof(KM_DRIVER_COMMAND));
	cout << "[+] Message has been sent to kernel (Get Process Id)." << endl;

	while (pCommand->code == 1 || pCommand->processId == NULL);
	return pCommand->processId;
}

int main()
{
	hMapFileW = OpenFileMapping(
		FILE_MAP_ALL_ACCESS,
		FALSE,
		L"Global\\MySharedMemory"
	);

	if (hMapFileW == INVALID_HANDLE_VALUE || hMapFileW == nullptr)
	{
		cerr << "Erreur lors de l'ouverture de la mémoire partagée." << endl;
		return EXIT_FAILURE;
	}

	const auto pCommand = (PKM_DRIVER_COMMAND)MapViewOfFile(
		hMapFileW,
		FILE_MAP_ALL_ACCESS,
		0,
		0,
		sizeof(KM_DRIVER_COMMAND)
	);

	if (pCommand == nullptr)
	{
		cerr << "Error MapViewOfFile(pCommand)" << endl;
		return EXIT_FAILURE;
	}

	GetProcessId(pCommand, "explorer.exe");

	printf("[-] Process Name : %s\n", pCommand->processName);
	printf("[-] Process ID   : 0x%p\n", pCommand->processId);

	// Release the allocated memory
	VirtualFree(pCommand->processName, 0, MEM_RELEASE);

	UnmapViewOfFile(pCommand);
	CloseHandle(hMapFileW);
	return EXIT_SUCCESS;
}
