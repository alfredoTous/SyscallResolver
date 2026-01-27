#include <windows.h>
#include <stdio.h>
#include "WinStructs.h"


// Struct containing syscall for Syswhispers2,3 implementation
typedef struct _SwSyscall{
    FARPROC Address;
    char* Name;
    DWORD SSN;
} SwSyscall, *PSwSyscall;


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


void GetSyscallsArr(IN HMODULE hModule, OUT SwSyscall** ppSyscallsArr, OUT size_t* pArrSize) {
    BYTE* pBase = (BYTE*)hModule;
    // DOS header
    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Failed to get IMAGE_DOS_HEADER\n");
        exit(1);
    }
    // Nt Header
    PIMAGE_NT_HEADERS pImgNtHdr = (PIMAGE_NT_HEADERS)(pBase+pImgDosHdr->e_lfanew);
    if (pImgNtHdr->Signature != IMAGE_NT_SIGNATURE) {
        printf("[-] Failed to get IMAGE_NT_SIGNATURE\n");
        exit(1);
    }
    
    // Getting Export Table from Optional Header
    PIMAGE_EXPORT_DIRECTORY pImgExpDir = (PIMAGE_EXPORT_DIRECTORY)(pBase+pImgNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);


    // Export table contains RVAs for arrays containing addresses of functions (including syscalls)
    // Getting Arrays
    DWORD* namesTable = (DWORD*)(pBase+pImgExpDir->AddressOfNames);
    DWORD* functionsTable = (DWORD*)(pBase+pImgExpDir->AddressOfFunctions);
    WORD* ordinalsTable = (WORD*)(pBase+pImgExpDir->AddressOfNameOrdinals);
    
    // First iteration for getting number of Syscalls in ntdll.dll 
    size_t ZwCounter = 0;
    for (size_t i=0; i<pImgExpDir->NumberOfFunctions; i++) {
        char* functionName = (char*)(pBase+namesTable[i]);
        if (strncmp(functionName, "Zw", 2) == 0) {
            ZwCounter++;
        }
    }
    
    // Allocate memory for array
    SwSyscall* ZwFunctions = (SwSyscall*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ZwCounter*sizeof(SwSyscall));
    
    // Second iteration 
    size_t idx = 0;
    for (size_t i=0; i<pImgExpDir->NumberOfFunctions; i++) {
        char* functionName = (char*)(pBase+namesTable[i]);

        WORD ordinal = ordinalsTable[i];
        // If api starts with Zw == Syscall
        if (strncmp(functionName, "Zw", 2) == 0) {
            FARPROC functionAddr = (FARPROC)(pBase+functionsTable[ordinal]);
            SwSyscall syscall = {.Address = functionAddr, .Name = functionName}; 
            ZwFunctions[idx] = syscall;
            idx++;
        }
    }

    // Return
    *ppSyscallsArr = ZwFunctions;
    *pArrSize = ZwCounter;
}


int comparator(const void* x_void, const void* y_void)
{
    SwSyscall* x_psyscall = (SwSyscall*)x_void;
    SwSyscall* y_psyscall = (SwSyscall*)y_void;

    if (x_psyscall->Address < y_psyscall->Address) return -1;
    if (x_psyscall->Address > y_psyscall->Address) return 1;
    return 0;
}


void SortSyscallsArr(OUT SwSyscall** ppSyscallsArr, IN size_t arrSize)
{
    qsort(*ppSyscallsArr, arrSize, sizeof(SwSyscall), comparator);
}


void SetSSNs(IN SwSyscall* syscallsArr, IN size_t arrSize)
{
    for (size_t i = 0; i < arrSize; i++) {
        syscallsArr[i].SSN = (DWORD)i;
    }
}


int main()
{
    HMODULE hNtdll = CustomGetModuleHandle(L"ntdll.dll");
    if (hNtdll == NULL) {
        printf("[-] CustomGetModuleHandle failed\n");
        exit(1);
    }

    SwSyscall* syscallsArr;
    size_t arrSize;
    GetSyscallsArr(hNtdll, &syscallsArr, &arrSize);

    // Sort Syscalls arr for Addresses, then index of the array will be equivalent to SSNs
    SortSyscallsArr(&syscallsArr, arrSize);
    
    // Set values to struct
    SetSSNs(syscallsArr, arrSize);

    for (size_t i=0; i<arrSize; i++) {
        printf("[i] %s: 0x%p -- SSN %d\n", syscallsArr[i].Name, syscallsArr[i].Address, syscallsArr[i].SSN);
    }
    HeapFree(GetProcessHeap(), NULL, syscallsArr);

    return 0;
}
