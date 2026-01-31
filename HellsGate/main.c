#include <windows.h>
#include <stdio.h>
#include "WinStructs.h"
#include "syscalls.h"

HMODULE CustomGetModuleHandle(wchar_t* moduleName)
{
    // Get PEB by offset in gs register
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    // Contains linked list of loaded modules
    PPEB_LDR_DATA pLdr = pPeb->Ldr;

    PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)pLdr->InMemoryOrderModuleList.Flink;
    PLDR_DATA_TABLE_ENTRY pStart = pDte;

    while (TRUE) {
        if (_wcsicmp(pDte->FullDllName.Buffer, moduleName) == 0) {
            wprintf(L"[+] Found %s: 0x%p \n", pDte->FullDllName.Buffer, (HMODULE)pDte->Reserved2[0]);
            // Return base address of module, which is the below member in official Windows struct
            return (HMODULE)pDte->Reserved2[0];
        }
        // Access next node through dereference
        pDte = *(PLDR_DATA_TABLE_ENTRY*)pDte;

        // Module not found in linked list full iteration
        if (pDte == pStart) {
            wprintf(L"[-] Module %s not found\n");
            return NULL;
        }
    }
}


DWORD GetSSnByNameImplementation(IN HMODULE hModule, IN char* syscallName)
{
    BYTE* pBase = (BYTE*)hModule;
    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Failed getting PIMAGE_DOS_HEADER\n");
        return NULL;
    }
    
    PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase+pImgDosHdr->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
        printf("[-] Failed getting PIMAGE_NT_HEADERS\n");
    }

    PIMAGE_EXPORT_DIRECTORY pImgExpDir = (PIMAGE_EXPORT_DIRECTORY)(pBase+pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* namesTable = (DWORD*)(pBase+pImgExpDir->AddressOfNames);
    DWORD* functionsTable = (DWORD*)(pBase+pImgExpDir->AddressOfFunctions);
    WORD* ordinalsTable = (WORD*)(pBase+pImgExpDir->AddressOfNameOrdinals);
    
    for (size_t i=0; i<pImgExpDir->NumberOfFunctions; i++) {
        char* functionName = (char*)(pBase+namesTable[i]);
        WORD ordinal = ordinalsTable[i];
        if (_stricmp(functionName, syscallName) == 0) {
            printf("[i] %s\n", functionName);
            // Function Address first bytes would be the syscall stub (assuming it ain't hooked)
            FARPROC functionAddr = (FARPROC)(pBase+functionsTable[ordinal]);

            // Parse bytes of stub, raw bytes
            size_t idx = 0;
            BYTE* bytes = (BYTE*)functionAddr;
            while (TRUE) {
                // If function ain't hooked stub will have the following opcodes 
                if (bytes[idx] == 0x4c && bytes[idx+1] == 0x8b && bytes[idx+2] == 0xd1 && // opcodes for (mov r10, rcx; mov eax, SSN)
                    bytes[idx+3] == 0xb8) {
                    // The SSN would start at the 5th byte
                    // We can easily get the value through dereference
                    DWORD SSN = *(DWORD*)(bytes+idx+4);
                    printf("\t[+] SSN: %d\n", SSN);
                    return SSN;
                }

                // If we got to this point function is probably hooked
                // We continue walking the bytes until the stub opcodes for the SSN are reached
                // If we reach opcodes for "syscall" or "ret" SSN was not found

                if (bytes[idx] == 0x0f && bytes[idx+1] == 0x05) return NULL; // opcodes for "syscall"
                if (bytes[idx] == 0xc3) return NULL; // opcode for "ret"
                idx++;
            }
        }
    }

}

// Wrapper for calling the actual function without having to pass HMODULE parameter
// This is the api to be exported on syscalls.h
DWORD GetSSNByName(IN char* syscallName) {
    HMODULE hNtdll = CustomGetModuleHandle(L"ntdll.dll");    
    DWORD SSN = GetSSnByNameImplementation(hNtdll, syscallName);
    return SSN;
}
