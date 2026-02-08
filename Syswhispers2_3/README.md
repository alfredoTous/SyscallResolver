## SysWhispers2 / SysWhispers3 — Address Sorting Technique

### Technique Explanation -- STEP BY STEP

1. **Get base address of ntdll.dll** : Since  `ntdll.dll` is load into every user-mode process there is no need to call `LoadLibrary` API.  
The base address (HMODULE) can be retrieved directly using `GetModuleHandle` WinApi.  
In this implementation, a custom `CustomGetModuleHandle` routine is used. It returns the same value as the standard WinAPI call and is included purely for educational purposes.

2. **Parse ntdll.dll** : Once the base address is obtained, the PE structure of `ntdll.dll` is parsed. recall the PE structure:
<p align="center">
<img src="https://0xrick.github.io/images/wininternals/pe2/1.png"
     alt="Portable Executable structure"
     width="350"/>
</p>

_Image source: https://0xrick.github.io/images/wininternals/pe2/1.png_

From the NT headers, the Optional Header is accessed in order to locate the **Data Directories**.  
The Export Directory is then retrieved, which contains all exported functions from the DLL, including syscalls.

3. **Get array of Syscalls from export table** : Having the export table all exported functions are iterated.
Since not all exported `Nt*` functions correspond to system calls, this implementation filters functions starting with the `Zw` prefix.  
The resulting list of `Zw*` exports is stored in an array, which is initially ordered alphabetically due to the layout of the export table.

4. **Sort syscalls by address** : Sorting the array by address will result in the SSNs being equivalent to the order by index

### Usage example implementing direct syscall
- Export the APIs

```c
//syscalls.h
#pragma once
#include <windows.h>

DWORD GetSSNByName(char* name);
BOOL InitSyscalls();
void CleanSyscalls();
```

- Import the APIs
```c
//test_exec.c
#include "syscalls.h"
```

- Before resolving any system call number, InitSyscalls() must be called.
This function parses the PE structure of ntdll.dll and allocates the internal syscall table.
```c
//test_exec.c
int main()
{
    BOOL status = InitSyscalls();
    if (status == FALSE) {
        printf("[-] Unexpected error initializating syscalls\n");
        exit(1);
    }
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
<img width="1003" height="530" alt="Image" src="https://github.com/user-attachments/assets/59380885-cedf-4830-9c08-c52482e23f39" />
