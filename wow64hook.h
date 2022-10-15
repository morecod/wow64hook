#ifndef _WOW64_HOOK_INC_
#define _WOW64_HOOK_INC_

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef HRESULT (WINAPI* TURBODISPATCHEXIT)(
    DWORD   /*Index*/, 
    DWORD*  /*ParamStack*/, 
    HRESULT /*Result*/
);

#define FUNC_TURBODISPATCHEXIT(x)                                              \
    HRESULT WINAPI x(DWORD Index, DWORD* ParamStack, HRESULT Result)

#define CHK_HRESULT()                                                          \
    if (FAILED(Result)) {                                                      \
        return Result;                                                         \
    }                                                                          \
    (VOID)(Result)

BOOL    WINAPI Wow64Hook_Initialize(VOID);
VOID    WINAPI Wow64Hook_Uninitialize(VOID);

#define WOW64_HOOK_ALL ((DWORD)-1)

VOID    WINAPI Wow64Hook_SSDT(DWORD Index, TURBODISPATCHEXIT Proc);
VOID    WINAPI Wow64Hook_SSDTShadow(DWORD Index, TURBODISPATCHEXIT Proc);
DWORD   WINAPI Wow64Hook_GetExitIp(VOID);
HRESULT WINAPI Wow64Hook_RecallService(VOID);

#ifdef __cplusplus
}
#endif

#endif // _WOW64_HOOK_INC_