#include <windows.h>
#include "syscalls.h"


int main()
{
    GetBuildVersion();
    printf("[+] SSN: %d\n", GetSSNByName("NtQueryInformationProcess"));
    
    return 0;
}
