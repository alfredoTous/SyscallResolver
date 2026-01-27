#pragma once
#include <windows.h>

DWORD GetSSNByName(char* name);
BOOL InitSyscalls();
void CleanSyscalls();
