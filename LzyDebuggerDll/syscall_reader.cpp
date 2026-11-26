#include "syscall_reader.h"
#include <Windows.h>

// 以十六进制打印机器码
UINT32 DumpSyscallIndex(LPCVOID addr)
{
    const BYTE* code = (const BYTE*)addr;
    UINT32 result = (UINT32)-1;

    __try
    {
        // stub 只有十几条指令，最多看前 32 字节，绝不无界扫描
        for (SIZE_T i = 0; i < 32; ++i)
        {
            if (code[i] == 0xC3 || code[i] == 0xCC)      // 已经走出 stub
                break;

            if (code[i] == 0x0F && code[i + 1] == 0x05)  // syscall
            {
                // mov eax, imm32 就在前面几条指令内（标准 stub 正好是 5 字节）
                for (SIZE_T back = 1; back <= 16 && back <= i; ++back)
                {
                    if (code[i - back] == 0xB8)
                    {
                        UINT32 v = *(const UINT32*)(code + (i - back) + 1);
                        if (v < 0x1000) { result = v; break; }   // 过滤立即数里的假 B8
                    }
                }
                break;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    return result;
}


std::vector<SyscallIdx> ReadSyscall()
{
    HMODULE hMod = GetModuleHandleA("ntdll.dll");

    if (hMod == NULL) return {};

    // 1. 定位 DOS 头 -> NT 头 -> 导出目录
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hMod;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return {};

    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)hMod + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return {};

    DWORD expRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (expRva == 0) return {};

    PIMAGE_EXPORT_DIRECTORY pExp =
        (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hMod + expRva);

    if (pExp == NULL) return {};

    DWORD* names = (DWORD*)((BYTE*)hMod + pExp->AddressOfNames);
    DWORD count = pExp->NumberOfNames;   // 按名字导出的函数数量

    std::vector<SyscallIdx> result;

    for (DWORD i = 0; i < count; i++) {
        const char* fnName = (const char*)((BYTE*)hMod + names[i]);
        FARPROC addr = GetProcAddress(hMod, fnName);
        if (addr != NULL) {
            bool x = false;
            //逆天，不放这个代码NtCreateFile可能读不出来，编程界的诡异事件，梗成真了。
            if (!strcmp(fnName, "NtCreateFile"));
            UINT32 index = DumpSyscallIndex(addr);
            if (index != -1)
            {
                SyscallIdx item = { fnName, index };
                result.push_back(item);
            }
        }
    }

    return result;
}
