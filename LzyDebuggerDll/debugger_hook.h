#ifndef DEBUGGER_HOOK_H
#define DEBUGGER_HOOK_H

#include "dll.h"
#include <Windows.h>

BOOL DLL WINAPI DebugBreakProcessHandler(
    IN HANDLE Process);

#endif
