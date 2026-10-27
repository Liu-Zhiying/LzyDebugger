#include "main.h"
#include "HookFunction.h"
#include "VirtualMemoryHelper.h"

#pragma data_seg()
VOID* pNtosKrnlBase = NULL;
VOID* pKeServiceDescriptorTable = NULL;
PMmCopyVirtualMemory pMmCopyVirtualMemory = NULL;
PTR_TYPE DirectoryTableBaseRVA;
GlobalManager* pGlobalManager = NULL;
#pragma data_seg()

#pragma code_seg("PAGE")
NTSTATUS DriverIOHandler(IN PDEVICE_OBJECT,
	IN PIRP Irp)
{
	PAGED_CODE();
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

#pragma code_seg("PAGE")
NTSTATUS DriverControlHandler(IN PDEVICE_OBJECT,
	IN PIRP Irp)
{
	PAGED_CODE();

	PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
	NTSTATUS           Status = STATUS_SUCCESS;
	ULONG_PTR          Info = 0;

	switch (IrpSp->Parameters.DeviceIoControl.IoControlCode)
	{

	case IOCTL_SET_KERNEL_RVA:
	{
		ULONG inLen = IrpSp->Parameters.DeviceIoControl.InputBufferLength;   // 输入
		//ULONG outLen = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;  // 输出

		//设置SSDT的地址

		if (inLen == sizeof(KernelRvaInfo))
		{
			KernelRvaInfo* pInfo = (KernelRvaInfo*)Irp->AssociatedIrp.SystemBuffer;

			VOID* pZwCreateFile = ZwCreateFile;

			pNtosKrnlBase = (VOID*)((PCHAR)pZwCreateFile - (ULONG_PTR)pInfo->ZwCreateFileRVA);
			pKeServiceDescriptorTable = (PCHAR)pNtosKrnlBase + (ULONG_PTR)pInfo->KeServiceDescriptorTableRVA;
			DirectoryTableBaseRVA = (PTR_TYPE)pInfo->DirectoryTableBaseRVA;
			pMmCopyVirtualMemory = (PMmCopyVirtualMemory)((PCHAR)pNtosKrnlBase + (ULONG_PTR)pInfo->MmCopyVirtualMemoryRVA);

			Info = sizeof(KernelRvaInfo);
		}
		break;
	}

	case IOCTL_START_VM_AND_HOOK:
	{
		//开始进行虚拟化
		pGlobalManager->vtxManager.EnterVirtualization();

		//启用进程HOOK
		pGlobalManager->eptHookManager.EnableProcessHook(DirectoryTableBaseRVA);

		//HookFunctionManager::HookSSDT(pKeServiceDescriptorTable, pGlobalManager);

		Info = 0;                                              // 纯写入，无返回长度
		break;
	}

	case IOCTL_STOP_VM_AND_UNHOOK:
	{
		//HookFunctionManager::UnhookSSDT(pGlobalManager);

		//禁用进程HOOK
		pGlobalManager->eptHookManager.DisableProcessHook();

		//开始退出虚拟化
		pGlobalManager->vtxManager.LeaveVirtualization();

		Info = 0;
		break;
	}
	case IOCTL_SET_SYSCALL_INDEX:
	{
		ULONG inLen = IrpSp->Parameters.DeviceIoControl.InputBufferLength;   // 输入

		if (inLen == sizeof(SyscallIndexIn))
		{
			SyscallIndexIn* pInfo = (SyscallIndexIn*)Irp->AssociatedIrp.SystemBuffer;

			HookFunctionManager::SetSyscallIndex(pInfo->functionName, pInfo->index);

			Info = inLen;
		}
		break;
	}
	case IOCTL_ADD_HOOK:
	{
		ULONG inLen = IrpSp->Parameters.DeviceIoControl.InputBufferLength;   // 输入
		//ULONG outLen = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;  // 输出

		if (inLen == sizeof(EptProcessHookRecordIn))
		{
			EptProcessHookRecordIn* pInfo = (EptProcessHookRecordIn*)Irp->AssociatedIrp.SystemBuffer;

			EptProcessHookRecord record = {};

			record.pOriginVirtAddr = pInfo->pOriginVirtAddr;
			record.pGotoVirtAddr = pInfo->pGotoVirtAddr;

			PEPROCESS pProcess = NULL;

			PsLookupProcessByProcessId((HANDLE)pInfo->processId, &pProcess);

			if (pProcess == NULL)
			{
				Status = STATUS_UNSUCCESSFUL;
				break;
			}

			//触发写时复制

			Status = TouchReadonlyCowPage(record.pOriginVirtAddr, pProcess);

			if (!NT_SUCCESS(Status))
				break;

			//锁定页面

			Status = LockVirtualMemory(pInfo->pOriginVirtAddr, pProcess);

			if (!NT_SUCCESS(Status))
				break;

			Status = LockVirtualMemory(pInfo->pGotoVirtAddr, pProcess);

			if (!NT_SUCCESS(Status))
				break;

			pGlobalManager->eptHookManager.AddProcessHook(record, pProcess);

			ObDereferenceObject(pProcess);

			Info = inLen;
		}
		break;
	}
	case IOCTL_REMOVE_HOOK:
	{
		ULONG inLen = IrpSp->Parameters.DeviceIoControl.InputBufferLength;   // 输入
		//ULONG outLen = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;  // 输出

		if (inLen == sizeof(EptProcessHookRecordIn))
		{
			EptProcessHookRecordIn* pInfo = (EptProcessHookRecordIn*)Irp->AssociatedIrp.SystemBuffer;

			PEPROCESS pProcess = NULL;

			PsLookupProcessByProcessId((HANDLE)pInfo->processId, &pProcess);

			if (pProcess == NULL)
			{
				Status = STATUS_UNSUCCESSFUL;
				break;
			}

			UnlockVirtualMemory(pInfo->pOriginVirtAddr, pProcess);

			UnlockVirtualMemory(pInfo->pGotoVirtAddr, pProcess);

			pGlobalManager->eptHookManager.RemoveProcessHook(pInfo->pOriginVirtAddr, pGlobalManager->eptHookManager.GetProcessCr3(pProcess));

			ObDereferenceObject(pProcess);

			Info = inLen;
		}
		break;
	}
	case IOCTL_READ_PROCESS_MEMORY:
	{
		Status = STATUS_UNSUCCESSFUL;

		LONG inLen = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
		ULONG outLen = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;

		if (inLen == sizeof(RwProcessMemoryIn) && outLen == sizeof(RwProcessMemoryIn))
		{
			RwProcessMemoryIn* pInfo = (RwProcessMemoryIn*)Irp->AssociatedIrp.SystemBuffer;

			PEPROCESS pProcess1 = NULL, pProcess2 = NULL;
			PMDL pMdl2 = NULL;
			PVOID pSysAddr2 = NULL;
			BOOLEAN bMdl2Locked = FALSE;
			KAPC_STATE apcState;
			BOOLEAN bAttached = FALSE;

			pInfo->nSizeRW = 0;

			do
			{
				if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pInfo->processId1, &pProcess1)))
					break;
				if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pInfo->processId2, &pProcess2)))
					break;

				/* ---- 锁定进程2的目标缓冲区 ---- */
				KeStackAttachProcess((PRKPROCESS)pProcess2, &apcState);
				bAttached = TRUE;

				pMdl2 = IoAllocateMdl(pInfo->pBaseAddress, (ULONG)pInfo->nSize, FALSE, FALSE, NULL);
				if (pMdl2 == NULL) break;

				__try {
					ProbeForRead(pInfo->pBaseAddress, pInfo->nSize, 1);
					MmProbeAndLockPages(pMdl2, UserMode, IoReadAccess);
					bMdl2Locked = TRUE;
				}
				__except (EXCEPTION_EXECUTE_HANDLER) {
					break;
				}

				pSysAddr2 = MmGetSystemAddressForMdlSafe(pMdl2, NormalPagePriority);
				if (pSysAddr2 == NULL) break;

				KeUnstackDetachProcess(&apcState);
				bAttached = FALSE;

				/* ---- 锁定进程1的源缓冲区 ---- */
				KeStackAttachProcess((PRKPROCESS)pProcess1, &apcState);
				bAttached = TRUE;

				__try {
					ProbeForWrite(pInfo->pBuffer, pInfo->nSize, 1);
					RtlCopyMemory(pInfo->pBuffer, pSysAddr2, pInfo->nSize);
					pInfo->nSizeRW = pInfo->nSize;
					Status = STATUS_SUCCESS;
				}
				__except (EXCEPTION_EXECUTE_HANDLER) {
					break;
				}

				KeUnstackDetachProcess(&apcState);
				bAttached = FALSE;

			} while (false);

			/* ---- 清理 ---- */
			if (bAttached)
				KeUnstackDetachProcess(&apcState);

			if (pMdl2 != NULL && bMdl2Locked)
			{
				KeStackAttachProcess((PRKPROCESS)pProcess2, &apcState);
				MmUnlockPages(pMdl2);
				KeUnstackDetachProcess(&apcState);
			}

			if (pMdl2 != NULL) IoFreeMdl(pMdl2);

			if (pProcess2 != NULL) ObDereferenceObject(pProcess2);
			if (pProcess1 != NULL) ObDereferenceObject(pProcess1);

			Info = inLen;
		}
		break;
	}
	case IOCTL_WRITE_PROCESS_MEMORY:
	{
		Status = STATUS_UNSUCCESSFUL;

		LONG inLen = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
		ULONG outLen = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;

		if (inLen == sizeof(RwProcessMemoryIn) && outLen == sizeof(RwProcessMemoryIn))
		{
			RwProcessMemoryIn* pInfo = (RwProcessMemoryIn*)Irp->AssociatedIrp.SystemBuffer;

			PEPROCESS pProcess1 = NULL, pProcess2 = NULL;
			PMDL pMdl1 = NULL;
			PVOID pSysAddr1 = NULL;
			BOOLEAN bMdl1Locked = FALSE;
			KAPC_STATE apcState;
			BOOLEAN bAttached = FALSE;

			pInfo->nSizeRW = 0;

			do
			{
				if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pInfo->processId1, &pProcess1)))
					break;
				if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pInfo->processId2, &pProcess2)))
					break;

				/* ---- 锁定进程1的目标缓冲区（将被写入） ---- */
				KeStackAttachProcess((PRKPROCESS)pProcess1, &apcState);
				bAttached = TRUE;

				pMdl1 = IoAllocateMdl(pInfo->pBuffer, (ULONG)pInfo->nSize, FALSE, FALSE, NULL);
				if (pMdl1 == NULL) break;

				__try {
					MmProbeAndLockPages(pMdl1, UserMode, IoReadAccess);
					bMdl1Locked = TRUE;
				}
				__except (EXCEPTION_EXECUTE_HANDLER) {
					break;
				}

				pSysAddr1 = MmGetSystemAddressForMdlSafe(pMdl1, NormalPagePriority);
				if (pSysAddr1 == NULL) break;

				KeUnstackDetachProcess(&apcState);
				bAttached = FALSE;

				/* ---- 锁定进程2的源缓冲区（读取来源） ---- */
				KeStackAttachProcess((PRKPROCESS)pProcess2, &apcState);
				bAttached = TRUE;

				__try {
					ProbeForWrite(pInfo->pBaseAddress, pInfo->nSize, 1);
					RtlCopyMemory(pInfo->pBaseAddress, pSysAddr1, pInfo->nSize);
					pInfo->nSizeRW = pInfo->nSize;
					Status = STATUS_SUCCESS;
				}
				__except (EXCEPTION_EXECUTE_HANDLER) {
					break;
				}

				KeUnstackDetachProcess(&apcState);
				bAttached = FALSE;

			} while (false);

			/* ---- 清理 ---- */
			if (bAttached)
				KeUnstackDetachProcess(&apcState);

			if (pMdl1 != NULL && bMdl1Locked)
			{
				KeStackAttachProcess((PRKPROCESS)pProcess1, &apcState);
				MmUnlockPages(pMdl1);
				KeUnstackDetachProcess(&apcState);
			}

			if (pMdl1 != NULL) IoFreeMdl(pMdl1);

			if (pProcess2 != NULL) ObDereferenceObject(pProcess2);
			if (pProcess1 != NULL) ObDereferenceObject(pProcess1);

			Info = inLen;
		}
		break;
	}
	case IOCTL_READ_PROCESS_MEMORY_2:
	{
		Status = STATUS_UNSUCCESSFUL;

		LONG inLen = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
		ULONG outLen = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;

		if (inLen == sizeof(RwProcessMemoryIn) && outLen == sizeof(RwProcessMemoryIn))
		{
			RwProcessMemoryIn* pInfo = (RwProcessMemoryIn*)Irp->AssociatedIrp.SystemBuffer;
			PEPROCESS pProcess1 = NULL, pProcess2 = NULL;

			pInfo->nSizeRW = 0;

			do
			{
				if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pInfo->processId1, &pProcess1)))
					break;
				if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pInfo->processId2, &pProcess2)))
					break;

				Status = pMmCopyVirtualMemory(pProcess2, pInfo->pBaseAddress, pProcess1, pInfo->pBuffer, pInfo->nSize, ExGetPreviousMode(), &pInfo->nSizeRW);

			} while (false);

			Info = inLen;
		}
		break;
	}
	case IOCTL_WRITE_PROCESS_MEMORY_2:
	{
		Status = STATUS_UNSUCCESSFUL;

		LONG inLen = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
		ULONG outLen = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;

		if (inLen == sizeof(RwProcessMemoryIn) && outLen == sizeof(RwProcessMemoryIn))
		{
			RwProcessMemoryIn* pInfo = (RwProcessMemoryIn*)Irp->AssociatedIrp.SystemBuffer;
			PEPROCESS pProcess1 = NULL, pProcess2 = NULL;

			pInfo->nSizeRW = 0;

			do
			{
				if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pInfo->processId1, &pProcess1)))
					break;
				if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pInfo->processId2, &pProcess2)))
					break;

				Status = pMmCopyVirtualMemory(pProcess1, pInfo->pBuffer, pProcess2, pInfo->pBaseAddress, pInfo->nSize, ExGetPreviousMode(), &pInfo->nSizeRW);

			} while (false);

			Info = inLen;
		}
		break;
	}
	default:
	{
		Status = STATUS_INVALID_DEVICE_REQUEST;                    // 4. 不识别的 IOCTL
		break;
	}
	}

	Irp->IoStatus.Status = Status;                            // 5. 回填结果
	Irp->IoStatus.Information = Info;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return Status;
}

#pragma code_seg("PAGE")
void UnloadDriver(IN PDRIVER_OBJECT drvObj)
{
	PAGED_CODE();
	PDEVICE_OBJECT devObj = drvObj->DeviceObject;
	if (devObj != NULL)
	{
		CallDestroyer(pGlobalManager);
		CallDestroyer(&GetSignletonMtrrMemoryTypeCache());
		CallDestroyer(&GetSignletonMtrrData());

		HookFunctionManager::Deinit();

		UNICODE_STRING symLinkName;
		RtlInitUnicodeString(&symLinkName, L"\\DosDevices\\VTXDriver");
		//如果你在DriverEntry里面调用IoCreateSymbolicLink的话加上这句
		//因为你在DriverEntry里面使用的常量跟着DriverEntry一起卸载了
		IoDeleteSymbolicLink(&symLinkName);
		IoDeleteDevice(devObj);
	}
	KdPrint(("VT-X driver has exited\n"));
}

#pragma code_seg("INIT")
extern "C" NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject,
	IN PUNICODE_STRING)
{
	//过ObRegisterCallbacks驱动签名检测
	PVOID thisDrvSection = pDriverObject->DriverSection;
	*((PUINT32)((PUCHAR)thisDrvSection + 0x68)) |= 0x20;

	pDriverObject->MajorFunction[IRP_MJ_CLOSE] =
		pDriverObject->MajorFunction[IRP_MJ_CREATE] =
		pDriverObject->MajorFunction[IRP_MJ_READ] =
		pDriverObject->MajorFunction[IRP_MJ_WRITE] = DriverIOHandler;
		
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverControlHandler;
	pDriverObject->DriverUnload = UnloadDriver;

	UINT32 initStep = 0;
	NTSTATUS status = STATUS_SUCCESS;
	PDEVICE_OBJECT fdo = NULL;
	UNICODE_STRING devName;
	UNICODE_STRING symLinkName;
	RtlInitUnicodeString(&devName, L"\\Device\\VTXDriver");
	RtlInitUnicodeString(&symLinkName, L"\\DosDevices\\VTXDriver");

	do
	{
		KdPrint(("DriverEntry(): Starting VT-X Driver\n"));

		status = IoCreateDevice(pDriverObject, sizeof(GlobalManager), &devName, FILE_DEVICE_UNKNOWN,
			0, FALSE, &fdo);
		if (!NT_SUCCESS(status))
			break;
		initStep = 1;

		status = IoCreateSymbolicLink(&symLinkName, &devName);
		if (!NT_SUCCESS(status))
			break;
		initStep = 2;

		GetSignletonMtrrData();
		GetSignletonMtrrMemoryTypeCache();

		//使用设备扩展初始化GlobalManager
		pGlobalManager = ((GlobalManager*)fdo->DeviceExtension);
		CallConstructor(pGlobalManager);

		HookFunctionManager::Init();

		//进入VM
		status = pGlobalManager->Init();
		if (!NT_SUCCESS(status))
			break;

		//暂时退出VM
		pGlobalManager->vtxManager.LeaveVirtualization();

		initStep = 3;

		fdo->Flags |= DO_BUFFERED_IO;
		KdPrint(("DriverEntry(): VT-X Driver Start successfully.\n"));
	} while (0);

	if (!NT_SUCCESS(status))
	{
		CHAR errorInfo[100] = {};
		sprintf(errorInfo, "DriverEntry(): VT-X Driver Init Err, Step: %d, Code: %x\n", initStep, status);
		KdPrint((errorInfo));
		switch (initStep)
		{
		case 3:
			CallDestroyer(pGlobalManager);
		case 2:
			IoDeleteSymbolicLink(&symLinkName);
		case 1:
			IoDeleteDevice(fdo);
		default:
			break;
		}
	}

	return status;
}

#pragma code_seg("PAGE")
void HookFunctionManager::SetSyscallIndex(char* pFunctionName, UINT32 index)
{
	KernelVector<SyscallIndexIn, MAIN_TAG, NonPaged>* pContainer = (KernelVector<SyscallIndexIn, MAIN_TAG, NonPaged>*)buffer;
	for (SIZE_TYPE idx = 0; idx < pContainer->Length(); ++idx)
	{
		//如果字符串匹配
		if (!strncmp(&(*pContainer)[idx].functionName[0], pFunctionName, sizeof (*pContainer)[idx].functionName))
		{
			(*pContainer)[idx].index = index;
			return;
		}
	}

	SyscallIndexIn item = { {}, index };
	strncpy_s(item.functionName, sizeof item.functionName, pFunctionName, strlen(pFunctionName));
	pContainer->PushBack(item);
}

#pragma code_seg("PAGE")
UINT32 HookFunctionManager::GetSyscallIndex(char* pFunctionName)
{
	KernelVector<SyscallIndexIn, MAIN_TAG, NonPaged>* pContainer = (KernelVector<SyscallIndexIn, MAIN_TAG, NonPaged>*)buffer;
	for (SIZE_TYPE idx = 0; idx < pContainer->Length(); ++idx)
	{
		//如果字符串匹配
		if (!strncmp(&(*pContainer)[idx].functionName[0], pFunctionName, sizeof(*pContainer)[idx].functionName))
			return (*pContainer)[idx].index;
	}

	return (UINT32)-1;
}
