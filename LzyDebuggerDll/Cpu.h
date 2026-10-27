#ifndef CPU_H
#define CPU_H

#include "dll.h"

#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

	void CPUString(char* outputString);
	bool DLL IsAMDCPU();
	bool DLL IsIntelCPU();

	void _vmcall(ULONG_PTR* rax, ULONG_PTR* rbx, ULONG_PTR* rcx, ULONG_PTR* rdx);
	void _vmmcall(ULONG_PTR* rax, ULONG_PTR* rbx, ULONG_PTR* rcx, ULONG_PTR* rdx);

	bool DLL IntelCpuIsInVirtualization();
	bool DLL AMDCpuIsInVirtualization();

#ifdef __cplusplus
}
#endif

#endif
