#ifndef DLL_API_HOOK_H
#define DLL_API_HOOK_H

#include <Windows.h>

PVOID FindDllApiX86(HMODULE hModule, LPCSTR functionName, DWORD& dwErrorCode);
PVOID FindDllApiX64(HMODULE hModule, LPCSTR functionName, DWORD& dwErrorCode);

DWORD HookDllApiX86(HMODULE hModule, LPCSTR functionName, PVOID& pOldFunctionPtr, PVOID pNewFunctionPtr);
DWORD HookDllApiX64(HMODULE hModule, LPCSTR functionName, PVOID& pOldFunctionPtr, PVOID pNewFunctionPtr);

#endif

