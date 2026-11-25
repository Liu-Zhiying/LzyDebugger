#ifndef PROCESS_THREAD_HELPER_H
#define PROCESS_THREAD_HELPER_H

#include "ntapi.h"
#include "HookFunction.h"

NTSTATUS CreateUserThread(PEPROCESS pProcess, PUSER_THREAD_START_ROUTINE pFunction, PVOID parameter, HANDLE* phThread, HANDLE* pThreadId);

#endif
