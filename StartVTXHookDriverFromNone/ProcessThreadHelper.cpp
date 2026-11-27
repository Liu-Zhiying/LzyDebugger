#include "ProcessThreadHelper.h"

struct CreateUserThreadInfo
{
	PUSER_THREAD_START_ROUTINE pFunction;
	PVOID parameter;
	HANDLE hUserThread;
	HANDLE userThreadId;
};

#pragma code_seg("PAGE")
VOID CreateUserThreadEntry(_In_ PVOID StartContext)
{
	OBJECT_ATTRIBUTES objectAttributes = {};
	CLIENT_ID clientId = { 0 };
	PS_ATTRIBUTE_LIST attrList = { 0 };

	attrList.TotalLength = sizeof(PS_ATTRIBUTE_LIST);

	attrList.Attributes[0].Attribute = 0x10003;
	attrList.Attributes[0].Size = sizeof(CLIENT_ID);
	attrList.Attributes[0].ValuePtr = &clientId; // 内核会将结果写到这里
	attrList.Attributes[0].ReturnLength = nullptr;

	//创建附加到特定进程的线程
	InitializeObjectAttributes(&objectAttributes, NULL, 0, NULL, NULL);

	UINT32 syscallIndex = HookFunctionManager::GetSyscallIndex("NtCreateThreadEx");

	KAPC_STATE apcState = {};

	if (syscallIndex == (UINT32)-1)
		PsTerminateSystemThread(STATUS_UNSUCCESSFUL);

	PNtCreateThreadEx pNtCreateThreadEx =
		(PNtCreateThreadEx)
		GetSubFunctionInSSDTByIndex(pKeServiceDescriptorTable, syscallIndex);

	if (pNtCreateThreadEx == NULL)
		PsTerminateSystemThread(STATUS_UNSUCCESSFUL);

	CreateUserThreadInfo* pInfo = (CreateUserThreadInfo*)StartContext;

	NTSTATUS status = pNtCreateThreadEx(&pInfo->hUserThread, THREAD_ALL_ACCESS, &objectAttributes, NtCurrentProcess(), pInfo->pFunction, pInfo->parameter, 0, 0, 0, 0, &attrList);

	pInfo->userThreadId = clientId.UniqueThread;

	PsTerminateSystemThread(status);
}

#pragma code_seg("PAGE")
NTSTATUS CreateUserThread(PEPROCESS pProcess, PUSER_THREAD_START_ROUTINE pFunction, PVOID parameter, HANDLE* phThread, HANDLE* pThreadId)
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

	CreateUserThreadInfo info = {};

	info.pFunction = pFunction;
	info.parameter = parameter;

	status = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, &objectAttributes, hProcess, &clientId, CreateUserThreadEntry, &info);

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

	if (NT_SUCCESS(threadExitStatus))
	{
		*phThread = info.hUserThread;
		*pThreadId = info.userThreadId;
	}

	ObDereferenceObject(pThread);

	return threadExitStatus;
}
