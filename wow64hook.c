#define _WIN32_WINNT    0x0601

#include "wow64hook.h"

#define STATIC static

#ifndef _ARRAYSIZE
#define _ARRAYSIZE(A) (sizeof(A)/sizeof((A)[0]))
#endif


#ifdef _MSC_VER
typedef volatile long T_VLONG;
#else
typedef long T_VLONG;
#endif

typedef DWORD64 (*SHELLPROC)();

#define T32Cast(type, x) ((type)((DWORD32)x))

#define SetTEB32Field(type, offset, value)                                     \
*(type*)((BYTE*)NtCurrentTeb() + offset) = value

#define GetTEB32Field(type, offset) (*(type*)((BYTE*)NtCurrentTeb() + offset))
#define TEB32_ProcessEnvironmentBlock (0x30)
#define TEB32_WOW32Reserved           (0xC0)
#define TEB32_SystemReserved1         (0xCC)
//
// we are using the field of SystemReserved 
//
#define TEB32_PROCESSING_FLAG         (TEB32_SystemReserved1 + 0x04)
#define TEB32_SAVE_TDINDEX            (TEB32_SystemReserved1 + 0x08)    // ecx
#define TEB32_SAVE_SYSINDEX           (TEB32_SystemReserved1 + 0x0C)    // eax
#define TEB32_SAVE_SYSPARAM           (TEB32_SystemReserved1 + 0x10)    // edx
#define TEB32_SAVE_TDRETN             (TEB32_SystemReserved1 + 0x14)    // eip
#define TEB32_SAVE_SRVFUNC            (TEB32_SystemReserved1 + 0x18)    // new service function

#define GetPEB32Field(type, peb32, offset) (*(type*)((BYTE*)peb32 + offset))
#define PEB32_OSMajorVersion          (0xA4)
#define PEB32_OSMinorVersion          (0xA8)
#define PEB32_OSBuildNumber           (0xAC)

#define SYS_SERVICE_TABLE_SIZE 4096

/******************************************************************************\
|*                                                                            *|
|*  base on https://github.com/rwfpl/rewolf-wow64ext/                         *|
|*                                                                            *|
\******************************************************************************/

#define X64_START_SHELLCODE                                                    \
    0x6A, 0x33,                                                                \
    0xE8, 0x00, 0x00, 0x00, 0x00,                                              \
    0x83, 0x04, 0x24, 0x05,                                                    \
    0xCB

#define X64_END_SHELLCODE                                                      \
    0xE8, 0x00, 0x00, 0x00, 0x00,                                              \
    0xC7, 0x44, 0x24, 0x04, 0x23, 0x00, 0x00, 0x00,                            \
    0x83, 0x04, 0x24, 0x0D,                                                    \
    0xCB

STATIC CONST BYTE X64_GetR15[] = {
    0x55,                           // push ebp
    0x8B, 0xEC,                     // mov ebp,esp
    0x83, 0xEC, 0x0C,               // sub esp,0C
    0x53,                           // push ebx
    0x56,                           // push esi
    0x0F, 0x57, 0xC0,               // xorps xmm0,xmm0
    0x57,                           // push edi
    0x66, 0x0F, 0x13, 0x45, 0xF8,   // movlpd [ebp-08],xmm0
    X64_START_SHELLCODE,
    0x49, 0x57,                     // push r15
    0x8F, 0x45, 0xF8,               // pop [rbp-8]
    X64_END_SHELLCODE,
    0x8B, 0x45, 0xF8,               // mov eax,[ebp-08]
    0x8B, 0x55, 0xFC,               // mov edx,[ebp-04]
    0x5F,                           // pop edi
    0x5E,                           // pop esi
    0x5B,                           // pop ebx
    0x8B, 0xE5,                     // mov esp,ebp
    0x5D,                           // pop ebp
    0xC3                            // retn
};

STATIC DWORD64 WINAPI ExecuteShellCode(BYTE* ShellCode, SIZE_T Size) {
    DWORD fOldProtect = 0;
    if(!VirtualProtect(ShellCode, Size, PAGE_EXECUTE_READWRITE, &fOldProtect)) {
        return 0ull;
    }
    DWORD64 iResult = ((SHELLPROC)ShellCode)();
    VirtualProtect(ShellCode, Size, fOldProtect, &fOldProtect);
    return iResult;
}

/******************************************************************************\
|*                                                                            *|
|*  Note:                                                                     *|
|*      in Wow64Process                                                       *|
|*      - register 'r13' is a 32-bit structural pointer                       *|
|*        which point to X86_SAVED_CONTEXT                                    *|
|*      - register 'r15' point to a turbo dispatch table                      *|
|*        it's also a 32-bit pointer                                          *|
|*                                                                            *|
\******************************************************************************/

typedef enum _TD_CONTEXT_VERSION {
    TDCtxVerUnknow,// unknow
    TDCtxVer1,     // win7 - win7sp1
    TDCtxVer2      // win8 - win10
}TD_CONTEXT_VERSION;

//
// using in win7 - win7sp1
//  
typedef struct _TD_CONTEXT_V1 {
    // CONTEXT Context;
    DWORD   Reserved[40];   // 0x00
    DWORD   Edi;            // 0xA0
    DWORD   Esi;            // 0xA4
    DWORD   Ebx;            // 0xA8
    DWORD   Edx;            // 0xAC
    DWORD   Ecx;            // 0xB0
    DWORD   Eax;            // 0xB4
    DWORD   Ebp;            // 0xB8
    DWORD   Eip;            // 0xBC
}TD_CONTEXT_V1, *PTD_CONTEXT_V1;

//
// using in win8 or latter
//
typedef struct _TD_CONTEXT_V2 {
    DWORD   Reserved[8];     // 0x00
    DWORD   Edi;             // 0x20
    DWORD   Esi;             // 0x24
    DWORD   Ebx;             // 0x28
    DWORD   Edx;             // 0x2C
    DWORD   Ecx;             // 0x30
    DWORD   Eax;             // 0x34
    DWORD   Ebp;             // 0x38
    DWORD   Eip;             // 0x3C
}TD_CONTEXT_V2, *PTD_CONTEXT_V2;

//---------------------------------------------------------------------------//
// global variable                                                           //
//---------------------------------------------------------------------------//

STATIC TD_CONTEXT_VERSION  g_TDCtxVersion = TDCtxVerUnknow;
STATIC DWORD64*            g_TDJumpAddressTablePtr = NULL;
STATIC DWORD               g_TDJumpAddressTableCount = 0;
STATIC DWORD64             g_TDJumpAddressTableData[64];
STATIC VOID*               g_SSDTExit[SYS_SERVICE_TABLE_SIZE];
STATIC VOID*               g_SSDTShadowExit[SYS_SERVICE_TABLE_SIZE];
STATIC TURBODISPATCHEXIT   g_SSDTFilter = NULL;
STATIC TURBODISPATCHEXIT   g_SSDTShadowFilter = NULL;
STATIC DWORD64             g_RelayFunction = 0ull;

STATIC TD_CONTEXT_VERSION WINAPI InitializeTDCtxVersion(VOID) {
    DWORD Peb32 = GetTEB32Field(DWORD, TEB32_ProcessEnvironmentBlock);
    DWORD osMajorVer = GetPEB32Field(DWORD, Peb32, PEB32_OSMajorVersion);
    DWORD osMinorVer = GetPEB32Field(DWORD, Peb32, PEB32_OSMinorVersion);
    WORD  osBuildNum = GetPEB32Field(WORD,  Peb32, PEB32_OSBuildNumber);

    // win10 - win10.0.19042.508 = CTX_VERSION_2
    if (osMajorVer == 10) {
        g_TDCtxVersion = TDCtxVer2;
        return TDCtxVer2;
    }
    // win8 - win8.1 = CTX_VERSION_2
    if (osMajorVer == 6 && osMinorVer >= 2) {
        g_TDCtxVersion = TDCtxVer2;
        return TDCtxVer2;
    }
    // win7 - win7sp1 = CTX_VERSION_1
    if (osMajorVer == 6 && osMinorVer == 1) {
        g_TDCtxVersion = TDCtxVer1;
        return TDCtxVer1;
    }

    g_TDCtxVersion = TDCtxVerUnknow;
    return TDCtxVerUnknow;
}

STATIC DWORD WINAPI InitializeTDJumpAddressTable(VOID) {
    DWORD64* rR15;
    rR15 = T32Cast(
        DWORD64*, ExecuteShellCode((BYTE*)X64_GetR15, sizeof(X64_GetR15))
    );
    
    MEMORY_BASIC_INFORMATION mbi;
    ZeroMemory(&mbi, sizeof(mbi));
    VirtualQuery(T32Cast(VOID*, rR15[0]), &mbi, sizeof(mbi));

    VOID* modWow64Cpu = mbi.AllocationBase;
    if (modWow64Cpu == NULL) {
        return 0;
    }

    g_TDJumpAddressTablePtr = NULL;
    ZeroMemory(g_TDJumpAddressTableData, sizeof(g_TDJumpAddressTableData));

    // number of turbo dispatch jump address & copy data
    DWORD i; 
    for(i = 0; i < _ARRAYSIZE(g_TDJumpAddressTableData); i++) {
        ZeroMemory(&mbi, sizeof(mbi));
        VirtualQuery(T32Cast(VOID*, rR15[i]), &mbi, sizeof(mbi));
        if (modWow64Cpu != mbi.AllocationBase) {
            g_TDJumpAddressTablePtr = rR15;
            return i;
        }
        g_TDJumpAddressTableData[i] = rR15[i];
    }

    // out of array
    return 0;
}

HRESULT WINAPI Wow64Hook_RecallService() {
    HRESULT hResult;
#ifdef _MSC_VER
    DWORD   rEsp;
    _asm mov[rEsp], esp;
    _asm mov esp, dword ptr fs : [TEB32_SAVE_SYSPARAM];  // sycall param stack
    _asm mov edx, esp;
    _asm mov ecx, dword ptr fs : [TEB32_SAVE_TDINDEX];   // turbo dispatch index
    _asm sub esp, 0x4;
    _asm mov eax, dword ptr fs : [TEB32_SAVE_SYSINDEX];  // syscall index
    _asm call dword ptr fs : [0xC0];
    _asm mov esp, [rEsp];
    _asm mov[hResult], eax;
#else
    __asm__ __volatile__("movl %fs:0xDC, %esp\n\t");     // sycall param stack
    __asm__ __volatile__("movl %esp, %edx\n\t");
    __asm__ __volatile__("movl %fs:0xD4, %ecx\n\t");     // turbo dispatch index
    __asm__ __volatile__("sub $0x4, %esp\n\t");
    __asm__ __volatile__("movl %fs:0xD8, %eax\n\t");     // syscall index
    __asm__ __volatile__("call *%fs:0xC0\n\t");
    __asm__ __volatile__("movl %%eax,%0\n\t":"=r"(hResult) : );
    __asm__ __volatile__("movl %ebp, %esp\n\t");
#endif
    return hResult;
}

#ifdef _MSC_VER
__declspec(naked)
#endif
STATIC VOID WINAPI TurboDispatchExitImpl() {
#ifdef _MSC_VER
    _asm pushad;
    _asm push eax;                                      // syscall result
    _asm push dword ptr fs:[TEB32_SAVE_SYSPARAM];       // sycall param stack
    // _asm push dword ptr fs:[TEB32_SAVE_TDINDEX];     // turbo dispatch index
    _asm push dword ptr fs:[TEB32_SAVE_SYSINDEX];       // syscall index
    _asm call dword ptr fs:[TEB32_SAVE_SRVFUNC];        // new service function
    _asm mov dword ptr [esp + 0x1C], eax;               // set new result
    _asm popad;
    _asm mov dword ptr fs:[TEB32_PROCESSING_FLAG], 0;   // clear processing flag
    _asm jmp dword ptr fs:[TEB32_SAVE_TDRETN];          // jmp to original ip
#else
    __asm__ __volatile__("popl %ebp\n\t");
    __asm__ __volatile__("pushal\n\t");
    __asm__ __volatile__("pushl %eax\n\t");             // syscall result
    __asm__ __volatile__("pushl %fs:0xDC\n\t");         // sycall param stack
    // __asm__ __volatile__("pushl %fs:0xD4\n\t");      // turbo dispatch index
    __asm__ __volatile__("pushl %fs:0xD8\n\t");         // syscall index
    __asm__ __volatile__("call *%fs:0xE4\n\t");         // new service function
    __asm__ __volatile__("movl %eax, 0x1C(%esp)\n\t");  // set new result
    __asm__ __volatile__("popal\n\t");
    __asm__ __volatile__("movl $0, %fs:0xD0\n\t");      // clear processing flag
    __asm__ __volatile__("jmp *%fs:0xE0\n\t");          // jmp to original ip
#endif
}

STATIC VOID WINAPI TurboDispatchJumpAddressEndImpl(
        DWORD TDContext,
        DWORD TDIndex,
        DWORD ServiceIndex, 
        DWORD ParamStack) {
    BOOL   isShadow = ((ServiceIndex & 0x1000) ? TRUE : FALSE);
    VOID** tblExit = isShadow ? g_SSDTShadowExit : g_SSDTExit;
    DWORD  srvIndex = ServiceIndex & 0x0FFF;
    VOID*  srvFunc = tblExit[srvIndex];
    if (srvFunc == NULL) {
        srvFunc = isShadow ? g_SSDTShadowFilter : g_SSDTFilter;
        if (srvFunc == NULL) {
            return ;
        }
    }
    
    if (GetTEB32Field(BOOL, TEB32_PROCESSING_FLAG)) {
        return;
    }

    SetTEB32Field(BOOL, TEB32_PROCESSING_FLAG, TRUE);
    SetTEB32Field(DWORD, TEB32_SAVE_SYSINDEX, ServiceIndex);
    SetTEB32Field(DWORD, TEB32_SAVE_SYSPARAM, ParamStack);
    SetTEB32Field(DWORD, TEB32_SAVE_SRVFUNC, (DWORD)srvFunc);

    DWORD* rEip = NULL;
    if (g_TDCtxVersion == TDCtxVer1) {
        rEip = &(T32Cast(TD_CONTEXT_V1*, TDContext)->Eip);
    }
    else if (g_TDCtxVersion == TDCtxVer2) {
        rEip = &(T32Cast(TD_CONTEXT_V2*, TDContext)->Eip);
    }
    else {
      return ;
    }

    SetTEB32Field(DWORD, TEB32_SAVE_TDRETN, *rEip);

    // for recall syscall
    SetTEB32Field(DWORD, TEB32_SAVE_TDINDEX, TDIndex);

    // set new turbo dispatch return ip
    *rEip = (DWORD)TurboDispatchExitImpl;
}

STATIC PVOID WINAPI BuildRelayFunction(VOID) {
    if (g_RelayFunction != 0ull) {
        return T32Cast(PVOID, g_RelayFunction);
    }

    BYTE* fnRelay = (BYTE*)VirtualAlloc(
        NULL, 4096/*One Page*/, MEM_COMMIT, PAGE_EXECUTE_READWRITE
    );
    if (fnRelay == NULL) {
        return NULL;
    }

    DWORD wrtLen = 0;

    // mov rdx, r11
    CONST BYTE bytsR11[] = { 0x49, 0x8B, 0xD3 };
    memcpy(fnRelay + wrtLen, bytsR11, sizeof(bytsR11));
    wrtLen += sizeof(bytsR11);
    
    // push rsi
    fnRelay[wrtLen] = 0x56;
    wrtLen += 1;

    // mov rsi, r13
    CONST BYTE bytsR13[] = { 0x49, 0x8B, 0xF5 };
    memcpy(fnRelay + wrtLen, bytsR13, sizeof(bytsR13));
    wrtLen += sizeof(bytsR13);

    // X64_End
    STATIC CONST BYTE bytsX64End[] = { X64_END_SHELLCODE };
    memcpy(fnRelay + wrtLen, bytsX64End, sizeof(bytsX64End));
    wrtLen += sizeof(bytsX64End);

    // pushad
    // push edx - Param Stack
    // push eax - System Service Index
    // push ecx - Turbo Dispatch Index
    // push esi - PX86_SAVED_CONTEXT
    fnRelay[wrtLen] = 0x60;
    fnRelay[wrtLen + 1] = 0x52;
    fnRelay[wrtLen + 2] = 0x50;
    fnRelay[wrtLen + 3] = 0x51;
    fnRelay[wrtLen + 4] = 0x56;
    wrtLen += 5;

    // call TurboDispatchJumpAddressEndImpl
    fnRelay[wrtLen] = 0xE8;
    *(DWORD*)(fnRelay + wrtLen + 1) = (
        (BYTE*)TurboDispatchJumpAddressEndImpl - (fnRelay + wrtLen) - 5
    );
    wrtLen += 5;

    // popad
    fnRelay[wrtLen] = 0x61;
    wrtLen += 1;

    // X64_START
    STATIC CONST BYTE bytsX64Start[] = { X64_START_SHELLCODE };
    memcpy(fnRelay + wrtLen, bytsX64Start, sizeof(bytsX64Start));
    wrtLen += sizeof(bytsX64Start);

    // pop rsi
    fnRelay[wrtLen] = 0x5E;
    wrtLen += 1;

    // 49 B8 5634120000000000 - mov r8, g_TurboDispatchTableData
    fnRelay[wrtLen] = 0x49;
    fnRelay[wrtLen + 1] = 0xB8;
    *(DWORD64*)(fnRelay + wrtLen + 2) = T32Cast(DWORD64, &g_TDJumpAddressTableData);
    wrtLen += 10;

    // 41 FF 24 C8 - jmp qword ptr[r8 + rcx * 8]
    CONST BYTE bytsJMP[] = {0x41, 0xFF, 0x24, 0xC8};
    memcpy(fnRelay + wrtLen, bytsJMP, sizeof(bytsJMP));
    wrtLen += sizeof(bytsJMP);

    g_RelayFunction = T32Cast(DWORD64, fnRelay);
    return fnRelay;
}

STATIC BOOL WINAPI DestoryRelayFunction(VOID) {
    if (g_RelayFunction == 0ull) {
        return TRUE;
    }
    if (VirtualFree(T32Cast(VOID*, g_RelayFunction), 0, MEM_RELEASE)) {
        g_RelayFunction = 0ull;
        return TRUE;
    }
    return FALSE;
}

BOOL WINAPI Wow64Hook_Initialize(VOID) {
    if (g_TDJumpAddressTableCount != 0) {
        return TRUE;
    }

    BOOL isWow64 = FALSE;
    IsWow64Process(GetCurrentProcess(), &isWow64);
    if (!isWow64) {
        return FALSE;
    }

    DWORD iCount = InitializeTDJumpAddressTable();
    if (iCount == 0) {
        return FALSE;
    }

    TD_CONTEXT_VERSION tdCtxVer = InitializeTDCtxVersion();
    if (tdCtxVer == TDCtxVerUnknow) {
    	return FALSE;
    }
    
    BYTE* wow32Reserved = GetTEB32Field(BYTE*, TEB32_WOW32Reserved);
    BYTE* TurboDispatchCtxInit = *(BYTE**)(wow32Reserved + 1);
    if (TurboDispatchCtxInit[0] == 0x41 &&
        TurboDispatchCtxInit[1] == 0xFF &&
        TurboDispatchCtxInit[2] == 0xA7) {
        iCount -= 2;
    }
    else {
        iCount -= 1; 
    }
    
    DWORD tblSize = iCount * sizeof(DWORD64);
    VOID* tblPtr = g_TDJumpAddressTablePtr;

    VOID* fnRelay = BuildRelayFunction();
    if (fnRelay == NULL) {
        return FALSE;
    }

    DWORD fOldProtect = 0;
    if (!VirtualProtect(tblPtr, tblSize, PAGE_EXECUTE_READWRITE, &fOldProtect)) {
        DestoryRelayFunction();
        return FALSE;
    }

    ZeroMemory(g_SSDTExit, sizeof(g_SSDTExit));
    ZeroMemory(g_SSDTShadowExit, sizeof(g_SSDTShadowExit));
    g_SSDTFilter = NULL;
    g_SSDTShadowFilter = NULL;

    DWORD i;
    for (i = 0; i < iCount; i++) {
        g_TDJumpAddressTablePtr[i] = g_RelayFunction;
    }
    VirtualProtect(tblPtr, tblSize, fOldProtect, &fOldProtect);
    g_TDJumpAddressTableCount = iCount;
    return TRUE;
}

VOID WINAPI Wow64Hook_Uninitialize(VOID) {
    if (g_TDJumpAddressTableCount == 0) {
        return ;
    }

    SetTEB32Field(BOOL, TEB32_PROCESSING_FLAG, TRUE);
    
    DWORD iCount  = g_TDJumpAddressTableCount;
    DWORD tblSize = iCount * sizeof(DWORD64);
    VOID* tblPtr  = g_TDJumpAddressTablePtr;

    DWORD fOldProtect = 0;
    if (VirtualProtect(tblPtr, tblSize, PAGE_EXECUTE_READWRITE, &fOldProtect)) {
        DWORD i;
        for (i = 0; i < iCount; i++) {
            g_TDJumpAddressTablePtr[i] = g_TDJumpAddressTableData[i];
        }
        VirtualProtect(tblPtr, tblSize, fOldProtect, &fOldProtect);
        Sleep(2000);
        DestoryRelayFunction();
        g_TDJumpAddressTablePtr = NULL;
        g_TDJumpAddressTableCount = 0;
        ZeroMemory(g_TDJumpAddressTableData, sizeof(g_TDJumpAddressTableData));
    }

    SetTEB32Field(BOOL, TEB32_PROCESSING_FLAG, FALSE);
}

DWORD WINAPI Wow64Hook_GetExitIp(VOID) {
    return GetTEB32Field(DWORD, TEB32_SAVE_TDRETN);
}

VOID WINAPI Wow64Hook_SSDT(DWORD Index, TURBODISPATCHEXIT Proc) {
    if (Index == WOW64_HOOK_ALL) {
        // it's making a greateful bug!!! I have no-idea
        InterlockedExchange((T_VLONG*)(&g_SSDTFilter), (LONG)Proc);
    }
    else if (Index < SYS_SERVICE_TABLE_SIZE) {
        InterlockedExchange((T_VLONG*)(&g_SSDTExit[Index]), (LONG)Proc);
    }
}

VOID WINAPI Wow64Hook_SSDTShadow(DWORD Index, TURBODISPATCHEXIT Proc) {
    if (Index == WOW64_HOOK_ALL) {
        InterlockedExchange((T_VLONG*)(&g_SSDTShadowFilter), (LONG)Proc);
    }
    else if (Index < SYS_SERVICE_TABLE_SIZE) {
        InterlockedExchange((T_VLONG*)(&g_SSDTShadowExit[Index]), (LONG)Proc);
    }
}

// int main() {
//     BOOL b = Wow64Hook_Initialize();
//     Wow64Hook_Uninitialize();
//     getchar();
//     return 0;
// }