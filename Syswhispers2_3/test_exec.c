#include <windows.h>
#include "WinStructs.h"
#include "syscalls.h"


// Structs needed to call NtQueryInformationProcess
typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PPEB PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;
typedef PROCESS_BASIC_INFORMATION *PPROCESS_BASIC_INFORMATION;

typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation = 0,
    ProcessDebugPort = 7,
    ProcessWow64Information = 26,
    ProcessImageFileName = 27,
    ProcessBreakOnTermination = 29
} PROCESSINFOCLASS;
// ----------------------------------------- //


// Declare NTAPI prototype
NTSTATUS CustomNtQueryInformationProcess(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

// Declare SSN_QueryInfoProcess
DWORD SSN_QueryInfoProcess = 0;


// Functions
//
// Init the global var SSNs values
void InitSSNs() {
    SSN_QueryInfoProcess = GetSSNByName("ZwQueryInformationProcess");
    printf("\n\n[+] FOUND SSN OF NtQueryInformationProcess: %d\n\n", SSN_QueryInfoProcess);
}


// Calling NtQueryInformationProcess for PROCESS_BASIC_INFORMATION
void TestSyscalls() {
    PROCESS_BASIC_INFORMATION pbi = {0};
    ULONG retLen = 0;

    NTSTATUS status = CustomNtQueryInformationProcess(
        GetCurrentProcess(),
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        &retLen
    );

    printf("=== ProcessBasicInformation ===\n");
    printf("[+] NTSTATUS        : 0x%X\n", status);
    printf("[+] Return Length   : %lu\n", retLen);
    printf("[+] PEB Address     : %p\n", pbi.PebBaseAddress);
    printf("[+] Process ID      : %llu\n\n",
           (unsigned long long)pbi.UniqueProcessId);

}


// Calling NtQueryInformationProcess for Full Image File Path
void TestSyscalls2() {
    BYTE buffer[512] = {0};
    UNICODE_STRING* imagePath = (UNICODE_STRING*)buffer;
    ULONG retLen = 0;

    NTSTATUS status = CustomNtQueryInformationProcess(
        GetCurrentProcess(),
        ProcessImageFileName,
        imagePath,
        sizeof(buffer),
        &retLen
    );

    printf("=== ProcessImageFileName ===\n");
    printf("[+] NTSTATUS        : 0x%X\n", status);
    printf("[+] Return Length   : %lu\n", retLen);

    if (status == 0 && imagePath->Buffer) {
        wprintf(L"[+] Image Path      : %.*s\n\n",
                imagePath->Length / sizeof(WCHAR),
                imagePath->Buffer);
    } else {
        printf("[-] Failed to query image path\n\n");
    }
}


int main()
{
    BOOL status = InitSyscalls();
    if (status == FALSE) {
        printf("[-] Unexpected error initializating syscalls\n");
        exit(1);
    }
    
    // Syscall usage example
    InitSSNs();
    printf("[!] Executing Syscalls example...\n");
    TestSyscalls();
    TestSyscalls2();


    CleanSyscalls();
    return 0;
}
