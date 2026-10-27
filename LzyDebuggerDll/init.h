#ifndef VTR3HOOKLIB_H
#define VTR3HOOKLIB_H

#include <Windows.h>
#include "dll.h"

#ifdef __cplusplus
extern "C" {
#endif

	bool DLL RedistStdout(HANDLE hRedist);
	void DLL SetConsoleReady();
	bool DLL InitDebuggerDriver();
	void DLL DeinitDebuggerDriver();
	void DLL HookFunction(PVOID pOriginAddr, PVOID pGotoAddr, UINT64 processId = GetCurrentProcessId());
	void DLL UnhookFunction(PVOID pOriginAddr, PVOID pGotoAddr, UINT64 processId = GetCurrentProcessId());

#ifdef __cplusplus
}
#endif

#endif // !

