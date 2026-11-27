#ifndef VIRTUAL_MEMORY_HELPER_H
#define VIRTUAL_MEMORY_HELPER_H

#include "ntapi.h"
#include "HookFunction.h"

NTSTATUS TouchReadonlyCowPage(_In_ PVOID pPage, _In_ PEPROCESS pProcess);
NTSTATUS LockVirtualMemory(_In_ PVOID pPage, _In_ PEPROCESS pProcess);
NTSTATUS UnlockVirtualMemory(_In_ PVOID pPage, _In_ PEPROCESS pProcess);

NTSTATUS AllocVirtualMemory(_In_ SIZE_T size, _In_ PEPROCESS pProcess, _Out_ PVOID* pMem);
NTSTATUS FreeVirtualMemory(_In_ PEPROCESS pProcess, _In_ PVOID pMem);
NTSTATUS WriteVirtualMemory(_In_ SIZE_T size, _In_ PEPROCESS pProcess, _Out_ PVOID pMemOut, _In_ PVOID pMemIn);
NTSTATUS ReadVirtualMemory(_In_ SIZE_T size, _In_ PEPROCESS pProcess, _Out_ PVOID pMemOut, _In_ PVOID pMemIn);

#endif
