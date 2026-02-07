#include <windows.h>
#include <stdio.h>
#include "WinStructs.h"

USHORT buildNumber = 0;
ULONG osMajorVersion = 0;
ULONG osMinorVersion = 0;

void GetBuildVersion()
{
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    buildNumber = pPeb->OSBuildNumber;
    osMajorVersion = pPeb->OSMajorVersion;
    osMinorVersion = pPeb->OSMinorVersion;
    printf("[+] BuildNumber: %hu\n", buildNumber);
    printf("[+] MajorVersion: %lu\n", osMajorVersion);
    printf("[+] MinorVersion: %lu\n", osMinorVersion);
}


int main()
{
    GetBuildVersion();

    return 0;
}
