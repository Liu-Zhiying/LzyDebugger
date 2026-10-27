# LzyDebugger
从0开始编写的虚拟化调试重构程序
## 组成
### AMDVTDriver
AMD SVM 驱动，从 [StartAMDVHookDriverFromNone](https://github.com/Liu-Zhiying/StartAMDVHookDriverFromNone) 而来，为了ring 3 hook 代码有修改
### StartVTXHookDriverFromNone
Intel VTX 驱动，从 [StartVTXHookDriverFromNone](https://github.com/Liu-Zhiying/StartVTXHookDriverFromNone) 而来，为了ring 3 hook 代码有修改
## LzyDebuggerConsole
测试用例
## LzyDebuggerDll
给驱动加载主程序提供用户态接口，和HOOK调试器对应API
## WebServer
提供调试符号缓存和其他web服务（符号缓存编写完毕，但是没有启用）

# 进度
重构了 NtReadVirtualMemory 和 NtWriteVirtualMemory.