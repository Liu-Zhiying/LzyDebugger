#ifndef DLL_H

#ifndef DLL_DEVELOPER
#define DLL __declspec(dllimport)
#else
#define DLL __declspec(dllexport)
#endif

#endif // !DLL_H

