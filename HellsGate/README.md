## HellsGate

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

3. **Inspect Syscall Stub** : Unlike the SysWhispers2/3 approach, Hell’s Gate does **not** rely on sorting syscall addresses.
Instead, execution jumps directly to the address of a specific exported function.  
If the function is not hooked, it will contain the standard syscall stub, from which the SSN can be extracted by inspecting the raw instructions.
If the function appears to be hooked, the implementation continues scanning nearby instructions until a valid syscall pattern is found.  
If no valid syscall stub is detected, SSN resolution fails for that function.  
This approach resolves syscall numbers **locally per stub**, without relying on global ordering assumptions.


### Usage example implementing direct syscall
- Export the API, only the resolver is required, as SSNs are extracted directly from the syscall stub at runtime

```c
//syscalls.h
#pragma once
#include <windows.h>

DWORD GetSSNByName(char* name);
```

- Import the API
```c
//test_exec.c
#include "syscalls.h"
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
<img width="987" height="528" alt="Image" src="https://github.com/user-attachments/assets/fede00ae-f769-4331-8d44-3686b3c4952c" />
