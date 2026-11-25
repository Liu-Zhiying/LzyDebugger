#include "VirtualMemoryHelper.h"

#pragma code_seg("PAGE")
VOID TouchReadonlyCowPageEntry(_In_ PVOID StartContext)
{
	UINT32 syscallIndex = HookFunctionManager::GetSyscallIndex("NtProtectVirtualMemory");

	if (syscallIndex == (UINT32)-1)
		PsTerminateSystemThread(STATUS_UNSUCCESSFUL);

	PNtProtectVirtualMemory pNtProtectVirtualMemory =
		(PNtProtectVirtualMemory)
		GetSubFunctionInSSDTByIndex(pKeServiceDescriptorTable, syscallIndex);

	if (pNtProtectVirtualMemory == NULL)
		PsTerminateSystemThread(STATUS_UNSUCCESSFUL);

	PVOID pPage = StartContext;
	SIZE_T size = 1;
	ULONG oldProtect = 0;
	NTSTATUS status = pNtProtectVirtualMemory(NtCurrentProcess(), &pPage, &size, PAGE_EXECUTE_READWRITE, &oldProtect);

	if (!NT_SUCCESS(status))
		PsTerminateSystemThread(status);

	__try
	{
		ProbeForRead(pPage, size, 1);
		ProbeForWrite(pPage, size, 1);
		//触发写时复制
		CHAR temp = *((volatile CHAR*)pPage);
		*((volatile CHAR*)pPage) = temp;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		PsTerminateSystemThread(STATUS_UNSUCCESSFUL);
	}

	pPage = StartContext;
	size = 1;

	pNtProtectVirtualMemory(NtCurrentProcess(), &pPage, &size, oldProtect, &oldProtect);

	PsTerminateSystemThread(STATUS_SUCCESS);
}

#pragma code_seg("PAGE")
VOID LockVirtualMemoryEntry(_In_ PVOID StartContext)
{
	UINT32 syscallIndex = HookFunctionManager::HookFunctionManager::GetSyscallIndex("NtLockVirtualMemory");

	if (syscallIndex == (UINT32)-1)
		PsTerminateSystemThread(STATUS_UNSUCCESSFUL);

	PNtLockVirtualMemory pNtLockVirtualMemory =
		(PNtLockVirtualMemory)
		GetSubFunctionInSSDTByIndex(pKeServiceDescriptorTable, syscallIndex);

	if (pNtLockVirtualMemory == NULL)
		PsTerminateSystemThread(STATUS_UNSUCCESSFUL);

	SIZE_T size = 1;

	PsTerminateSystemThread(pNtLockVirtualMemory(NtCurrentProcess(), &StartContext, &size, 1));
}

#pragma code_seg("PAGE")
VOID UnlockVirtualMemoryEntry(_In_ PVOID StartContext)
{
	UINT32 syscallIndex = HookFunctionManager::GetSyscallIndex("NtUnlockVirtualMemory");

	if (syscallIndex == (UINT32)-1)
		PsTerminateSystemThread(STATUS_UNSUCCESSFUL);

	PNtUnlockVirtualMemory pNtUnlockVirtualMemory =
		(PNtUnlockVirtualMemory)
		GetSubFunctionInSSDTByIndex(pKeServiceDescriptorTable, syscallIndex);

	if (pNtUnlockVirtualMemory == NULL)
		PsTerminateSystemThread(STATUS_UNSUCCESSFUL);

	SIZE_T size = 1;

	PsTerminateSystemThread(pNtUnlockVirtualMemory(NtCurrentProcess(), &StartContext, &size, 1));
}

struct AllocVirtualMemoryInfo
{
	SIZE_T size;
	PVOID pMem;
};

#pragma code_seg("PAGE")
VOID AllocVirtualMemoryEntry(_In_ PVOID StartContext)
{
	UINT32 syscallIndex = HookFunctionManager::GetSyscallIndex("NtAllocateVirtualMemory");

	if (syscallIndex == (UINT32)-1)
		PsTerminateSystemThread(STATUS_UNSUCCESSFUL);

	PNtAllocateVirtualMemory pNtAllocateVirtualMemory =
		(PNtAllocateVirtualMemory)
		GetSubFunctionInSSDTByIndex(pKeServiceDescriptorTable, syscallIndex);

	if (pNtAllocateVirtualMemory == NULL)
		PsTerminateSystemThread(STATUS_UNSUCCESSFUL);

	AllocVirtualMemoryInfo* pInfo = (AllocVirtualMemoryInfo*)StartContext;

	pInfo->pMem = NULL;

	NTSTATUS status = pNtAllocateVirtualMemory(NtCurrentProcess(), &pInfo->pMem, NULL, &pInfo->size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	PsTerminateSystemThread(status);
}

#pragma code_seg("PAGE")
VOID FreeVirtualMemoryEntry(_In_ PVOID StartContext)
{
	UINT32 syscallIndex = HookFunctionManager::GetSyscallIndex("NtFreeVirtualMemory");

	if (syscallIndex == (UINT32)-1)
		PsTerminateSystemThread(STATUS_UNSUCCESSFUL);

	PNtFreeVirtualMemory pNtFreeVirtualMemory =
		(PNtFreeVirtualMemory)
		GetSubFunctionInSSDTByIndex(pKeServiceDescriptorTable, syscallIndex);

	if (pNtFreeVirtualMemory == NULL)
		PsTerminateSystemThread(STATUS_UNSUCCESSFUL);

	NTSTATUS status = pNtFreeVirtualMemory(NtCurrentProcess(), &StartContext, 0, MEM_RELEASE);

	PsTerminateSystemThread(status);
}

#pragma code_seg("PAGE")
NTSTATUS TouchReadonlyCowPage(_In_ PVOID pPage, _In_ PEPROCESS pProcess)
{
	HANDLE hThread = NULL;
	HANDLE hProcess = NULL;
	PETHREAD pThread = NULL;
	CLIENT_ID clientId = {};
	OBJECT_ATTRIBUTES objectAttributes = {};

	//创建附加到特定进程的线程
	InitializeObjectAttributes(&objectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

	// 2. 设置 ClientId，指定目标进程的 PID
	clientId.UniqueProcess = (HANDLE)PsGetProcessId(pProcess); // 你的目标进程 ID
	clientId.UniqueThread = NULL;

	// 3. 调用 ZwOpenProcess
	NTSTATUS status = ZwOpenProcess(
		&hProcess,
		0,
		&objectAttributes,
		&clientId
	);

	if (!NT_SUCCESS(status))
		return status;

	status = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, &objectAttributes, hProcess, &clientId, TouchReadonlyCowPageEntry, pPage);

	if (!NT_SUCCESS(status))
	{
		ZwClose(hProcess);
		return status;
	}

	ZwClose(hProcess);

	//等待线程

	status = ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, (PVOID*)&pThread, NULL);

	if (!NT_SUCCESS(status))
	{
		ZwClose(hThread);
		return status;
	}

	ZwClose(hThread);

	while (PsGetThreadExitStatus(pThread) == STATUS_PENDING) continue;

	//读取线程返回值，释放资源，返回

	NTSTATUS threadExitStatus = PsGetThreadExitStatus(pThread);

	ObDereferenceObject(pThread);

	return threadExitStatus;
}

#pragma code_seg("PAGE")
NTSTATUS LockVirtualMemory(_In_ PVOID pPage, _In_ PEPROCESS pProcess)
{
	HANDLE hThread = NULL;
	HANDLE hProcess = NULL;
	PETHREAD pThread = NULL;
	CLIENT_ID clientId = {};
	OBJECT_ATTRIBUTES objectAttributes = {};

	//创建附加到特定进程的线程
	InitializeObjectAttributes(&objectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

	// 2. 设置 ClientId，指定目标进程的 PID
	clientId.UniqueProcess = (HANDLE)PsGetProcessId(pProcess); // 你的目标进程 ID
	clientId.UniqueThread = NULL;

	// 3. 调用 ZwOpenProcess
	NTSTATUS status = ZwOpenProcess(
		&hProcess,
		0,
		&objectAttributes,
		&clientId
	);

	if (!NT_SUCCESS(status))
		return status;

	status = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, &objectAttributes, hProcess, &clientId, LockVirtualMemoryEntry, pPage);

	if (!NT_SUCCESS(status))
	{
		ZwClose(hProcess);
		return status;
	}

	ZwClose(hProcess);

	//等待线程

	status = ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, (PVOID*)&pThread, NULL);

	if (!NT_SUCCESS(status))
	{
		ZwClose(hThread);
		return status;
	}

	ZwClose(hThread);

	while (PsGetThreadExitStatus(pThread) == STATUS_PENDING) continue;

	//读取线程返回值，释放资源，返回

	NTSTATUS threadExitStatus = PsGetThreadExitStatus(pThread);

	ObDereferenceObject(pThread);

	return threadExitStatus;
}

#pragma code_seg("PAGE")
NTSTATUS UnlockVirtualMemory(_In_ PVOID pPage, _In_ PEPROCESS pProcess)
{
	HANDLE hThread = NULL;
	HANDLE hProcess = NULL;
	PETHREAD pThread = NULL;
	CLIENT_ID clientId = {};
	OBJECT_ATTRIBUTES objectAttributes = {};

	//创建附加到特定进程的线程
	InitializeObjectAttributes(&objectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

	// 2. 设置 ClientId，指定目标进程的 PID
	clientId.UniqueProcess = (HANDLE)PsGetProcessId(pProcess); // 你的目标进程 ID
	clientId.UniqueThread = NULL;

	// 3. 调用 ZwOpenProcess
	NTSTATUS status = ZwOpenProcess(
		&hProcess,
		0,
		&objectAttributes,
		&clientId
	);

	if (!NT_SUCCESS(status))
		return status;

	status = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, &objectAttributes, hProcess, &clientId, UnlockVirtualMemoryEntry, pPage);

	if (!NT_SUCCESS(status))
	{
		ZwClose(hProcess);
		return status;
	}

	ZwClose(hProcess);

	//等待线程

	status = ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, (PVOID*)&pThread, NULL);

	if (!NT_SUCCESS(status))
	{
		ZwClose(hThread);
		return status;
	}

	ZwClose(hThread);

	while (PsGetThreadExitStatus(pThread) == STATUS_PENDING) continue;

	//读取线程返回值，释放资源，返回

	NTSTATUS threadExitStatus = PsGetThreadExitStatus(pThread);

	ObDereferenceObject(pThread);

	return threadExitStatus;
}

NTSTATUS AllocVirtualMemory(SIZE_T size, PEPROCESS pProcess, PVOID* pMem)
{
	HANDLE hThread = NULL;
	HANDLE hProcess = NULL;
	PETHREAD pThread = NULL;
	CLIENT_ID clientId = {};
	OBJECT_ATTRIBUTES objectAttributes = {};

	//创建附加到特定进程的线程
	InitializeObjectAttributes(&objectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

	// 2. 设置 ClientId，指定目标进程的 PID
	clientId.UniqueProcess = (HANDLE)PsGetProcessId(pProcess); // 你的目标进程 ID
	clientId.UniqueThread = NULL;

	// 3. 调用 ZwOpenProcess
	NTSTATUS status = ZwOpenProcess(
		&hProcess,
		0,
		&objectAttributes,
		&clientId
	);

	if (!NT_SUCCESS(status))
		return status;

	AllocVirtualMemoryInfo info = {};

	info.size = size;

	status = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, &objectAttributes, hProcess, &clientId, AllocVirtualMemoryEntry, &info);

	if (!NT_SUCCESS(status))
	{
		ZwClose(hProcess);
		return status;
	}

	ZwClose(hProcess);

	//等待线程

	status = ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, (PVOID*)&pThread, NULL);

	if (!NT_SUCCESS(status))
	{
		ZwClose(hThread);
		return status;
	}

	ZwClose(hThread);

	while (PsGetThreadExitStatus(pThread) == STATUS_PENDING) continue;

	//读取线程返回值，释放资源，返回

	NTSTATUS threadExitStatus = PsGetThreadExitStatus(pThread);

	ObDereferenceObject(pThread);

	*pMem = info.pMem;

	return threadExitStatus;
}

NTSTATUS FreeVirtualMemory(PEPROCESS pProcess, PVOID pMem)
{
	HANDLE hThread = NULL;
	HANDLE hProcess = NULL;
	PETHREAD pThread = NULL;
	CLIENT_ID clientId = {};
	OBJECT_ATTRIBUTES objectAttributes = {};

	//创建附加到特定进程的线程
	InitializeObjectAttributes(&objectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

	// 2. 设置 ClientId，指定目标进程的 PID
	clientId.UniqueProcess = (HANDLE)PsGetProcessId(pProcess); // 你的目标进程 ID
	clientId.UniqueThread = NULL;

	// 3. 调用 ZwOpenProcess
	NTSTATUS status = ZwOpenProcess(
		&hProcess,
		0,
		&objectAttributes,
		&clientId
	);

	if (!NT_SUCCESS(status))
		return status;

	status = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, &objectAttributes, hProcess, &clientId, UnlockVirtualMemoryEntry, pMem);

	if (!NT_SUCCESS(status))
	{
		ZwClose(hProcess);
		return status;
	}

	ZwClose(hProcess);

	//等待线程

	status = ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, (PVOID*)&pThread, NULL);

	if (!NT_SUCCESS(status))
	{
		ZwClose(hThread);
		return status;
	}

	ZwClose(hThread);

	while (PsGetThreadExitStatus(pThread) == STATUS_PENDING) continue;

	//读取线程返回值，释放资源，返回

	NTSTATUS threadExitStatus = PsGetThreadExitStatus(pThread);

	ObDereferenceObject(pThread);

	return threadExitStatus;
}

NTSTATUS WriteVirtualMemory(_In_ SIZE_T size, _In_ PEPROCESS pProcess, _Out_ PVOID pMemOut, _In_ PVOID pMemIn)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	PMDL pMdl = NULL;
	PVOID pSysAddr = NULL;
	BOOLEAN bMdlLocked = FALSE;
	KAPC_STATE apcState;
	BOOLEAN bAttached = FALSE;

	do
	{
		/* ---- 锁定进程2的目标缓冲区 ---- */
		KeStackAttachProcess((PRKPROCESS)pProcess, &apcState);
		bAttached = TRUE;

		pMdl = IoAllocateMdl(pMemOut, (ULONG)size, FALSE, FALSE, NULL);
		if (pMdl == NULL) break;

		__try {
			ProbeForRead(pMemOut, size, 1);
			MmProbeAndLockPages(pMdl, UserMode, IoReadAccess);
			bMdlLocked = TRUE;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			break;
		}

		pSysAddr = MmGetSystemAddressForMdlSafe(pMdl, NormalPagePriority);
		if (pSysAddr == NULL) break;

		KeUnstackDetachProcess(&apcState);
		bAttached = FALSE;

		RtlCopyMemory(pSysAddr, pMemIn, size);

		status = STATUS_SUCCESS;

	} while (false);

	/* ---- 清理 ---- */
	if (bAttached)
		KeUnstackDetachProcess(&apcState);

	if (pMdl != NULL && bMdlLocked)
	{
		KeStackAttachProcess((PRKPROCESS)pProcess, &apcState);
		MmUnlockPages(pMdl);
		KeUnstackDetachProcess(&apcState);
	}

	if (pMdl != NULL) IoFreeMdl(pMdl);

	return status;
}

NTSTATUS ReadVirtualMemory(_In_ SIZE_T size, _In_ PEPROCESS pProcess, _Out_ PVOID pMemOut, _In_ PVOID pMemIn)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	PMDL pMdl = NULL;
	PVOID pSysAddr = NULL;
	BOOLEAN bMdlLocked = FALSE;
	KAPC_STATE apcState;
	BOOLEAN bAttached = FALSE;

	do
	{
		/* ---- 锁定进程2的目标缓冲区 ---- */
		KeStackAttachProcess((PRKPROCESS)pProcess, &apcState);
		bAttached = TRUE;

		pMdl = IoAllocateMdl(pMemIn, (ULONG)size, FALSE, FALSE, NULL);
		if (pMdl == NULL) break;

		__try {
			ProbeForRead(pMemIn, size, 1);
			bMdlLocked = TRUE;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			break;
		}

		pSysAddr = MmGetSystemAddressForMdlSafe(pMdl, NormalPagePriority);
		if (pSysAddr == NULL) break;

		KeUnstackDetachProcess(&apcState);
		bAttached = FALSE;

		RtlCopyMemory(pMemOut, pSysAddr, size);

		status = STATUS_SUCCESS;

	} while (false);

	/* ---- 清理 ---- */
	if (bAttached)
		KeUnstackDetachProcess(&apcState);

	if (pMdl != NULL && bMdlLocked)
	{
		KeStackAttachProcess((PRKPROCESS)pProcess, &apcState);
		MmUnlockPages(pMdl);
		KeUnstackDetachProcess(&apcState);
	}

	if (pMdl != NULL) IoFreeMdl(pMdl);

	return status;
}
