#ifndef DLLINJECT_H
#define DLLINJECT_H

#include "dll.h"
#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif
	bool DLL InjectDllByRemoteThread(UINT64 processId, LPCSTR dllPath);
	HANDLE DLL CreateSuspendedProcess(LPCSTR cmdLine);
#ifdef __cplusplus
}
#endif

#endif
