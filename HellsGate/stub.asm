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
