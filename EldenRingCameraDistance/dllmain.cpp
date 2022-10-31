// dllmain.cpp : Defines the entry point for the DLL application.
#include "framework.h"
#include "ModUtils.h"

#include <vector>
#include <xmmintrin.h>

//constexpr unsigned int ASM_PROC_SIZE = 5;
constexpr unsigned int JMP_SIZE = 14;

extern "C"
{
    uintptr_t ReturnAddress;
    void CameraDistance();
    __m128 CameraDistanceMul = _mm_set_ss(1.0025f);
    __m128 CameraDistanceAdd = _mm_set_ss(0.05f);
}

DWORD WINAPI MainThread(LPVOID lpParam)
{
    //std::vector<uint16_t> original({ 0xF3, 0x0F, 0x11, 0xBB, 0xB8, 0x01, 0x00, 0x00 });
    //std::vector<uint8_t> replacement({ 0xE8, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90});
    std::vector<uint16_t> original({ 0xF3, 0x0F, 0x11, 0xBB, 0xB8, 0x01 });
    std::vector<uint8_t> replacement({ 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 }); // ff 25 00 00 00 00
    uintptr_t hookAddress = ModUtils::SigScan(original);
    if (hookAddress)
    {
        uintptr_t targetAddress = (uintptr_t)&CameraDistance;
        ModUtils::Log("Target address: %p", targetAddress);
    //    uintptr_t relativeAddress = (uintptr_t)&CameraDistance - (hookAddress + 5);
    //    replacement[1] = relativeAddress & 0xFF;
    //    replacement[2] = (relativeAddress & 0xFF00) >> 8;
    //    replacement[3] = (relativeAddress & 0xFF0000) >> 16;
    //    replacement[4] = (relativeAddress & 0xFF000000) >> 24;
    //    ReturnAddress = hookAddress - ((uintptr_t)&CameraDistance + ASM_PROC_SIZE);
        ModUtils::Replace(hookAddress, original, replacement);
        //ModUtils::MemCopy(hookAddress, (uintptr_t)0x0000000025ff, 6);
        ModUtils::MemCopy(hookAddress + (JMP_SIZE - 8), (uintptr_t)&targetAddress, 8);
        ReturnAddress = hookAddress + JMP_SIZE;
    }
    ModUtils::CloseLog();
    return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        CreateThread(0, 0, &MainThread, 0, 0, NULL);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

