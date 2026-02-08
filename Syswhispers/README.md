## SysWhispers (Build-Based Technique)

### Technique Explanation

This technique consists of **hardcoding system call numbers (SSNs)** and determining the **Windows OS version at runtime** in order to select the correct value.

To identify the operating system version, the **PEB (Process Environment Block)** is used, which provides access to the following fields:

- `OSBuildNumber`
- `OSMajorVersion`
- `OSMinorVersion`

---

### SSN Generation

To simplify and automate the implementation, a **Python script** was developed to generate syscall resolver functions for specific NTAPIs.

The script parses ta syscall mapping dataset from:

[https://github.com/j00ru/windows-syscalls/blob/master/x64/json/nt-per-syscall.json](https://github.com/j00ru/windows-syscalls/blob/master/x64/json/nt-per-syscall.json)

---

### Usage example implementing direct syscall

- Use python generator with desired syscall
```bash
python3 generator.py -f "NtQueryInformationProcess"
```

- The python script outputs the function to be pasted into resolver implementation
```c
//main.c
DWORD GetSSN_NtQueryInformationProcess()
{
    // Windows Vista
    if (osMajorVersion == 6 && osMinorVersion == 0) {
        if (buildNumber == 6000) return 22; // SP0
        if (buildNumber == 6001) return 22; // SP1
        if (buildNumber == 6002) return 22; // SP2
    }

    // Windows 7
    if (osMajorVersion == 6 && osMinorVersion == 1) {
        if (buildNumber == 7600) return 22; // SP0
        if (buildNumber == 7601) return 22; // SP1
    }

     // Windows 8
    if (osMajorVersion == 6 && osMinorVersion == 2) {
        if (buildNumber == 9200) return 23; // 8.0
    }

    // Windows 8.1
    if (osMajorVersion == 6 && osMinorVersion == 3) {
        if (buildNumber == 9600) return 24; // 8.1
    }
    
    // Windows 10/11/Server
    if (osMajorVersion == 10 && osMinorVersion == 0) {
        switch (buildNumber) {
            // Windows 10
            case 10240: return 25; // 1507
            case 10586: return 25; // 1511
            case 14393: return 25; // 1607
            case 15063: return 25; // 1703
            case 16299: return 25; // 1709
            case 17134: return 25; // 1803
            case 17763: return 25; // 1809
            case 18362: return 25; // 1903
            case 18363: return 25; // 1909
            case 19041: return 25; // 2004
            case 19042: return 25; // 20H2
            case 19043: return 25; // 21H1
            case 19044: return 25; // 21H2
            case 19045: return 25; // 22H2
            
            // Windows 11/Server
            case 20348: return 25; // Server 2022
            case 22000: return 25; // 11 21H2
            case 22621: return 25; // 11 22H2
            case 22631: return 25; // 11 23H2
            case 25398: return 25; // Server 23H2
            case 26100: return 25; // 11 24H2 / Server 2025
            case 26200: return 25; // 11 25H2

            default:
                // For unknow builds return latest
                if (buildNumber >= 22000) return 25; // Last Windows 11
                if (buildNumber >= 10240) return 25; // Last Windows 10
                return 0;

        }
    }
    return 0;
}
```

- Wrapper for facilitating usage
```c
//main.c
DWORD GetSSNByName(char* functionName) 
{
    if (_stricmp(functionName, "NtQueryInformationProcess") == 0) {
        return GetSSN_NtQueryInformationProcess();
    }
    printf("[-] Api not found, add function to wrapper");
    return NULL;
}
``` 

- Export APIs
```c
//syscalls.h
#pragma once
#include <windows.h>

void GetBuildVersion();
DWORD GetSSNByName(char* functionName);
```
- Import APIs
```c
//test_exec.c
#include "syscalls.h"
```
- Before resolving any system call number, GetBuildVersion() must be called to resolve the OS build version
```c
int main()
{
    GetBuildVersion();
}
```
- For direct syscall we would need to define syscall stub in assembly
```masm
;stub.asm
EXTERN SSN_QueryInfoProcess:DWORD

.CODE

PUBLIC CustomNtQueryInformationProcess

CustomNtQueryInformationProcess PROC    ; Syscall Stub
    mov     r10, rcx
    mov     eax, SSN_QueryInfoProcess   ; Load SSN to eax at runtime
    syscall                           ; Exec Syscall
    ret
CustomNtQueryInformationProcess ENDP

END
```

- Declare the prototype of CustomNtQueryInformationProcess and global variable SSN_QueryInfoprocess, notice it should be the same names as in the stub.asm
```c
//test_exec.c
NTSTATUS CustomNtQueryInformationProcess(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

// Declare SSN_QueryInfoProcess
DWORD SSN_QueryInfoProcess = 0;
```

- Resolve the SSN
```c
//test_exec.c
void InitSSNs() {
    SSN_QueryInfoProcess = GetSSNByName("ZwQueryInformationProcess");
    printf("\n\n[+] FOUND SSN OF NtQueryInformationProcess: %d\n\n", SSN_QueryInfoProcess);
}
```

- Execute syscall
```c
//test_exec.c
    NTSTATUS status = CustomNtQueryInformationProcess(
        GetCurrentProcess(),
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        &retLen
    );
```

### Demo
<img width="1013" height="549" alt="Image" src="https://github.com/user-attachments/assets/423a3add-1715-42df-8141-91ba212d3c09" />

