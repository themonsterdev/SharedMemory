#include <Windows.h>
#include <aclapi.h>
#include <iostream>

// Shared Memory
// https://github.com/fengjixuchui/SharedMemory-By-Frankoo/tree/master
// https://github.com/IAmTapped/Rust-Cheat-Shared-Memory-Driver/tree/main

using namespace std;

typedef struct _KM_REQUEST_GET_PROCESS_HANDLE
{
	int count;
}KM_REQUEST_GET_PROCESS_HANDLE, * PKM_REQUEST_GET_PROCESS_HANDLE;

// shared memory mapping
HANDLE hMapFileW = NULL;

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

	auto pRequestPointer = MapViewOfFile(
		hMapFileW,
		FILE_MAP_ALL_ACCESS,
		0,
		0,
		sizeof(KM_REQUEST_GET_PROCESS_HANDLE)
	);

	if (pRequestPointer == nullptr)
	{
		cerr << "Error MapViewOfFile(pRequestPointer)" << endl;
		return EXIT_FAILURE;
	}

	PKM_REQUEST_GET_PROCESS_HANDLE pRequest = (PKM_REQUEST_GET_PROCESS_HANDLE)pRequestPointer;
	cout << "GetProcessId : " << pRequest->count << endl;

	UnmapViewOfFile(pRequestPointer);

	CloseHandle(hMapFileW);

	return EXIT_SUCCESS;
}
