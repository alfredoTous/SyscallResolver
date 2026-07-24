#include <windows.h>
#include <stdio.h>
#include "WinStructs.h"


// Global var
PVOID pNtdll = NULL;

PVOID GetBaseAddressOfNtdll()
{
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    return ((PLDR_DATA_TABLE_ENTRY)((PBYTE)(pPeb->Ldr->InMemoryOrderModuleList.Flink->Flink)-0x10))->DllBase;
}


DWORD GetSSNByNameImplementation(IN PVOID pNtdll, IN char* syscallName)
{
    // Get Export Directory of ntdll.dll
    PBYTE pBase = (PBYTE)pNtdll;
    PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)(pBase+pDosHdr->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY expDir =  (PIMAGE_EXPORT_DIRECTORY)(pBase+pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    // ----------------------------------- // 

    // Itereate exported functions from Export Directory
    DWORD* functionsTable = (DWORD*)(pBase+expDir->AddressOfFunctions);
    DWORD* namesTable = (DWORD*)(pBase+expDir->AddressOfNames);
    WORD* ordinalsTable = (WORD*)(pBase+expDir->AddressOfNameOrdinals);

    // Tartarus Gate vars 
    int RANGE = 500; 
    int DOWN = 32;
    int UP = -32;
    
    
    DWORD SSN;

    for (size_t i=0; i<expDir->NumberOfFunctions; i++) {
        char* functionName = (char*)(pBase+namesTable[i]);
        WORD ordinal = ordinalsTable[i];
        if (_stricmp(functionName, syscallName) == 0) {
            FARPROC functionAddress = (FARPROC)(pBase+functionsTable[i]);
            PBYTE bytes = (PBYTE)functionAddress;
            // Simulating Hook
            // Changing page permission
            DWORD oldProtect;
            VirtualProtect(bytes, 10, PAGE_EXECUTE_READWRITE, &oldProtect);
            bytes[3] = 0xe9;
            VirtualProtect(bytes, 10, oldProtect, &oldProtect);
            for (int j=0; j<32; j++) {
                if (j % 8 == 0 ) printf("\n");
                printf("%2X ", bytes[j]);
            }
            printf("\n");
            while (TRUE) {
                if (bytes[0] == 0x4c && bytes[1] == 0x8b && bytes[2] == 0xd1 && bytes[3] == 0xb8) {
                    SSN = *(DWORD*)(bytes+4);
                    printf("[+]SSN -- %d\n", SSN);
                    return SSN;
                }
               
                // Tartarus Gate Logic
                if (bytes[0] == 0xe9 || bytes[3] == 0xe9); {  // opcode for JMP instruction 
                    for (size_t idx=1; idx<RANGE; idx++) {
                        // Check DOWN
                        if (bytes[0+idx*DOWN] == 0x4c && bytes[1+idx*DOWN] == 0x8b
                            && bytes[2+idx*DOWN] == 0xd1 && bytes[3+idx*DOWN] == 0xb8) {
                            SSN = *(DWORD*)(bytes+4+idx*DOWN) - idx;
                            printf("TARTARUS GATE DOWN\n[+]SSN -- %d\n", SSN);
                            return SSN;
                        }
                        // Check UP
                        if (bytes[0+idx*UP] == 0x4c && bytes[1+idx*UP] == 0x8b
                            && bytes[2+idx*UP] == 0xd1 && bytes[3+idx*UP] == 0xb8) {
                            SSN = *(DWORD*)(bytes+4+idx*UP) + idx;
                            printf("TARTARUS GATE UP\n[+]SSN -- %d\n", SSN);
                            return SSN;
                        }

                    }
                }

            }
        }
    } 


    
}


DWORD GetSSNByName(IN char* syscallName)
{
    return GetSSNByNameImplementation(pNtdll, syscallName);
}


int main()
{
    pNtdll = GetBaseAddressOfNtdll();
    GetSSNByName("NtQueryInformationProcess");
}
