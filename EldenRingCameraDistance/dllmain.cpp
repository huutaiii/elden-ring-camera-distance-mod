// dllmain.cpp : Defines the entry point for the DLL application.
#include "framework.h"
#include "../include/ModUtils.h"
#include "../include/INIReader.h"
#include "resource.h"

#include <vector>
#include <xmmintrin.h>
#include <iostream>
#include <fstream>

constexpr unsigned int JMP_SIZE = 14;

HMODULE g_hModule;
INIReader config;

extern "C"
{
    uintptr_t ReturnAddress;
    void CameraDistance();
    __m128 CameraDistanceMul;
    __m128 CameraDistanceAdd;

    void CameraInterp();
    __m128 InterpSpeedMul;
    uintptr_t InterpReturn;
    void CamInterpAlt();
    __m128 vInterpSpeedMul;
    uintptr_t InterpRetAlt;

    void LoadingEnd();
    void LoadingBegin();
    uintptr_t LoadingEndReturn;
    uintptr_t LoadingBeginReturn;
}

constexpr bool USE_CAM_INTERP_ALT = true;

std::string GetDefaultConfig()
{
    HMODULE handle = g_hModule;
    HRSRC rs = ::FindResourceW(handle, MAKEINTRESOURCE(IDR_CONFIGFILE), MAKEINTRESOURCE(TEXTFILE));
    if (rs)
    {
        HGLOBAL rsData = ::LoadResource(handle, rs);
        size_t size = ::SizeofResource(handle, rs);
        if (rsData)
        {
            const char* data = static_cast<const char*>(::LockResource(rsData));
            return std::string(data, size);
        }
    }
    return std::string();
}

void LoadConfig()
{
    std::string configPath = ModUtils::GetModuleFolderPath() + "\\config.ini";
    INIReader reader(configPath);

    if (reader.ParseError())
    {
        ModUtils::Log("Cannot load config file");
        ModUtils::Log("creating default config");

        std::string configDefault = GetDefaultConfig();
        std::ofstream configFile;
        configFile.open(configPath);
        configFile << configDefault;
        configFile.close();

        reader = INIReader(configPath);
    }

    if (!reader.ParseError())
    {
        ModUtils::Log("Reading config");

        float multiplier = reader.GetFloat("camera_distance", "multiplier", 1.f);
        ModUtils::Log("using multiplier = %f", multiplier);
        CameraDistanceMul = _mm_set_ss(multiplier);

        float offset = reader.GetFloat("camera_distance", "flat_offset", 0.f);
        ModUtils::Log("using offset = %f", offset);
        CameraDistanceAdd = _mm_set_ss(offset);
    }

    config = reader;
}

bool HookLoadState()
{
    {
        std::vector<uint16_t> bytes({ 0x4C, 0x63, 0x43, 0x48, 0x4D, 0x03, 0xC0, 0x48, 0x8B, 0x43, 0x10, 0x48, 0x8B, 0xD6, 0x48, 0x8B, 0xCB });
        uintptr_t hookAddress = ModUtils::SigScan(bytes);
        if (!hookAddress)
        {
            return false;
        }
        uintptr_t toAddress = (uintptr_t)&LoadingBegin;
        ModUtils::MemCopy(toAddress, hookAddress, bytes.size());
        ModUtils::Hook(hookAddress, toAddress, bytes.size() - 14);
        LoadingBeginReturn = hookAddress + bytes.size();
    }

    {
        std::vector<uint16_t> bytes({ 0x48, 0x8B, 0xC4, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57 });
        uintptr_t hookAddress = ModUtils::SigScan(bytes);
        if (!hookAddress)
        {
            return false;
        }
        uintptr_t toAddress = (uintptr_t)&LoadingEnd;
        ModUtils::MemCopy(toAddress, hookAddress, bytes.size());
        ModUtils::Hook(hookAddress, toAddress);
        LoadingEndReturn = hookAddress + bytes.size();
    }
    return true;
}

bool HookPivotInterp()
{
    float follow_speed_multiplier = config.GetFloat("camera_interpolation", "follow_speed_multiplier", 1.f);
    float speed_mul_z = config.GetFloat("camera_interpolation", "follow_speed_multiplier_z", 0.f);
    ModUtils::Log("using follow_speed_multiplier = %f", follow_speed_multiplier);
    ModUtils::Log("using follow_speed_multiplier_z = %f", speed_mul_z);
    InterpSpeedMul = _mm_set_ss(follow_speed_multiplier);
    vInterpSpeedMul = (speed_mul_z > 0.f) ? _mm_setr_ps(follow_speed_multiplier, speed_mul_z, follow_speed_multiplier, 0.f)
        : _mm_setr_ps(follow_speed_multiplier, follow_speed_multiplier, follow_speed_multiplier, 0.f);

    InterpReturn = 0;
    if (!USE_CAM_INTERP_ALT)
    {
        // 16 bytes
        std::vector<uint16_t> bytes = { 0xF3, 0x41, 0x0F, 0x10, 0x10, 0x0F, 0x57, 0xC9, 0x48, 0x8B, 0x44, 0x24, 0x70, 0x0F, 0x28, 0xDA };
        uintptr_t hookAddress = ModUtils::SigScan(bytes);
        if (hookAddress)
        {
            uintptr_t toAddress = (uintptr_t)&CameraInterp;

            // copy original instructions over to the custom function
            // does not work with incremental linking
            ModUtils::MemCopy(toAddress, hookAddress, bytes.size());

            ModUtils::Hook(hookAddress, toAddress, 2); // 16 bytes stolen - 14 bytes jump
            InterpReturn = hookAddress + bytes.size();
        }
        return hookAddress != 0;
    }
    else
    {
        std::vector<uint16_t> bytes = { 0x44, 0x0F, 0x28, 0x00, 0x0F, 0x28, 0xC4, 0x41, 0x0F, 0x5C, 0x21, 0x0F, 0x5C, 0xC6 }; // 14B
        InterpRetAlt = ModUtils::SigScanAndHook(bytes, &CamInterpAlt);
        return InterpRetAlt != 0;
    }
}

DWORD WINAPI MainThread(LPVOID lpParam)
{
    LoadConfig();
    std::vector<uint16_t> original({ 0xF3, 0x0F, 0x11, 0xBB, 0xB8, 0x01 }); // movss [rbx + 1B8], xmm7 (2 MSBytes truncated)
    std::vector<uint8_t> replacement({ 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 }); // ff 25 00 00 00 00
    uintptr_t hookAddress = ModUtils::SigScan(original);
    if (hookAddress)
    {
        uintptr_t targetAddress = (uintptr_t)&CameraDistance;

        ModUtils::Log("Applying patch at %p", hookAddress);
        ModUtils::Log("Target address: %p", targetAddress);

        ModUtils::Replace(hookAddress, original, replacement);
        ModUtils::MemCopy(hookAddress + (JMP_SIZE - 8), (uintptr_t)&targetAddress, 8);
        ReturnAddress = hookAddress + JMP_SIZE;
    }
    else
    {
        ModUtils::RaiseError(ModUtils::GetModuleName() + ": Search failed. Nothing is modified.");
    }

    if (config.GetBoolean("camera_interpolation", "disable_lag", false))
    {
        ModUtils::Log("Disabling camera lag");
        if (config.GetBoolean("camera_interpolation", "disable_lag_alt", false) == false)
        {
            // cmp byte ptr [rbx+00000315], 00
            // ; signature starts here
            // je eldenring.exe+3B5726 
            // xorps xmm1, xmm1
            // movaps[rbx + 00000210], xmm1
            std::vector<uint16_t> signature({ 0x74, 0x1E, 0x0F, 0x57, 0xC9, 0x0F, 0x29, 0x8B, 0x10, 0x02, 0x00, 0x00 });
            uintptr_t hookAddress = ModUtils::SigScan(signature);
            if (hookAddress)
            {
                // replace the jump with nop's
                ModUtils::Replace(hookAddress, std::vector<uint16_t>({ 0x74, 0x1E }), std::vector<uint8_t>({ 0x90, 0x90 }));
            }
        }
        else
        {
            std::vector<uint16_t> signature({ 0x66, 0x0F, 0x7F, 0x07, 0xF3, 0x0F, 0x10, 0xAB, 0x90, 0x01, 0x00, 0x00 });
            uintptr_t hookAddress = ModUtils::SigScan(signature);
            if (hookAddress)
            {
                ModUtils::Replace(hookAddress, {0x66, 0x0f, 0x7f, 0x07}, {0x90, 0x90, 0x90, 0x90});
            }
        }
    }

    //if (config.GetBoolean("camera_interpolation", "use_interpolation", false))
    {
        //if (HookPivotInterpCtrl())
        {
            HookPivotInterp();
        }
    }

    ModUtils::CloseLog();
    return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    g_hModule = hModule;
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

