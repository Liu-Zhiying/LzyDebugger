#ifndef VIRTUAL_MEMORY_HELPER_H
#define VIRTUAL_MEMORY_HELPER_H

#include "ntapi.h"
#include "HookFunction.h"

NTSTATUS TouchReadonlyCowPage(_In_ PVOID pPage, _In_ PEPROCESS pProcess);
NTSTATUS LockVirtualMemory(_In_ PVOID pPage, _In_ PEPROCESS pProcess);
NTSTATUS UnlockVirtualMemory(_In_ PVOID pPage, _In_ PEPROCESS pProcess);

#endif
