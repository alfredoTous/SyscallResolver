#include <windows.h>
#include "syscalls.h"


int main()
{
    BOOL status = InitSyscalls();
    if (status == FALSE) {
        printf("[-] Unexpected error initializating syscalls\n");
        exit(1);
    }

    DWORD dwCreateThreadExSSN = GetSSNByName("ZwCreateThreadEx");

    printf("[+] Testing SSN: %d\n", dwCreateThreadExSSN);
    CleanSyscalls();
    return 0;
}
