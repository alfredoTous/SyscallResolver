#include <windows.h>
#include <stdio.h>
//#include <winternl.h>
#include "structs.h"


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


int main()
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    HMODULE hNtdll2 = CustomGetModuleHandle(L"ntdll.dll");
    if (hNtdll2 == NULL) {
        printf("[-] CustomGetModuleHandle failed, exiting...\n");
        exit(1);
    }
    printf("[i] 0x%p vs 0x%p\n", hNtdll, hNtdll2);
    return 0;
}
