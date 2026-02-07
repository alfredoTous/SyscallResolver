#include <windows.h>
#include <stdio.h>
#include "WinStructs.h"
#include "syscalls.h"

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


// Output from `generator.py -f "NtQueryInformationProcess"`
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


// Wrapper to export
DWORD GetSSNByName(char* functionName) 
{
    if (_stricmp(functionName, "NtQueryInformationProcess") == 0) {
        return GetSSN_NtQueryInformationProcess();
    }
    printf("[-] Api not found, add function to wrapper");
    return NULL;
}
