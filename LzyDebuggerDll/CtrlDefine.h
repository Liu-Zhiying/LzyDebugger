#ifndef CTRL_DEFINE_H
#define CTRL_DEFINE_H

#ifndef DRIVER_USE
#include <Windows.h>
#else
#include <ntddk.h>
#endif

#ifndef CTL_CODE
#define CTL_CODE( DeviceType, Function, Method, Access ) (                 \
    ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
)
#endif

//一些类型别名
typedef unsigned char UINT8;
typedef char SINT8;
typedef unsigned short UINT16;
typedef short SINT16;
typedef unsigned int UINT32;
typedef int SINT32;
typedef unsigned long long UINT64;
typedef long long SINT64;
#if defined(_WIN64)
typedef UINT64 SIZE_TYPE;
typedef UINT64 PTR_TYPE;
#else
typedef UINT32 SIZE_TYPE;
typedef UINT32 PTR_TYPE;
#endif

#define IOCTL_SET_KERNEL_RVA CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_START_VM_AND_HOOK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_STOP_VM_AND_UNHOOK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ADD_HOOK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REMOVE_HOOK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_PHYSICAL_ADDRESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_SYSCALL_INDEX CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
//自己实现的内存读写
#define IOCTL_WRITE_PROCESS_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_READ_PROCESS_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)
//调用MmCopyVirtualMemory的内存读写
#define IOCTL_WRITE_PROCESS_MEMORY_2 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_READ_PROCESS_MEMORY_2 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80A, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _KernelRvaInfo {
    void* ZwCreateFileRVA;
    void* KeServiceDescriptorTableRVA;
    void* DirectoryTableBaseRVA;
    void* MmCopyVirtualMemoryRVA;
} KernelRvaInfo, * PKernelRvaInfo;

typedef struct _SyscallIndex {
    char functionName[260];
    UINT32 index;
} SyscallIndexIn, * PSyscallIndexIn;

struct EptProcessHookRecordIn
{
    PTR_TYPE processId;
    PVOID pOriginVirtAddr;
    PVOID pGotoVirtAddr;
#pragma code_seg()
    EptProcessHookRecordIn() : pOriginVirtAddr(NULL), processId(0), pGotoVirtAddr(NULL) {}
};

struct NptProcessHookRecordIn
{
    PTR_TYPE processId;
    PVOID pOriginVirtAddr;
    PVOID pGotoVirtAddr;
#pragma code_seg()
    NptProcessHookRecordIn() : pOriginVirtAddr(NULL), processId(0), pGotoVirtAddr(NULL) {}
};

struct RwProcessMemoryIn
{
    PVOID pBaseAddress;
    PVOID pBuffer;
    SIZE_T nSize;
    SIZE_T nSizeRW;
    UINT64 processId1;
    UINT64 processId2;

    RwProcessMemoryIn() : pBaseAddress(NULL), pBuffer(NULL), nSize(0), nSizeRW(0), processId1(0), processId2(0) {}
};

#endif