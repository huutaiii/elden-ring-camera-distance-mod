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
    void CameraDistanceAlt();
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

    {
        std::ofstream file;
        file.open(ModUtils::GetModuleFolderPath() + "\\config_default.ini");
        file << ";don't edit this file, it's here just to show the default configuration" << std::endl;
        file << GetDefaultConfig();
        file.close();
    }

    if (reader.ParseError())
    {
        ModUtils::Log("Cannot load config file");
        ModUtils::Log("creating default config");

        std::string configDefault = GetDefaultConfig();
        std::ofstream configFile;
        configFile.open(configPath);
        configFile << ";delete this file to restore mod defaults" << std::endl;
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

bool HookCameraDistance()
{
    std::vector<uint16_t> bytes({ 0x48, 0x8D, 0x4C, 0x24, 0x20, 0x44, 0x0F, 0x28, 0xD8, 0xF3, 0x45, 0x0F, 0x59, 0xDF });
    if (true)
    {
        ReturnAddress = ModUtils::SigScanAndHook(bytes, &CameraDistance);
    }
    else
    {
        ReturnAddress = 0;
        uintptr_t hookAddr = ModUtils::SigScan(bytes);

        if (hookAddr)
        {
            ModUtils::Log("Creating jump to %p", (uintptr_t)&CameraDistance);
            ModUtils::MemCopy((uintptr_t)&CameraDistance, hookAddr, 5);
            uintptr_t targetAddr = (uintptr_t)&CameraDistance - (hookAddr + 5);
            ModUtils::Log("Relative address: %d", targetAddr);
            *((char*)hookAddr) = 0xE9u;
            ModUtils::MemCopy(hookAddr + 1, (uintptr_t)&targetAddr, 4);
            ReturnAddress = hookAddr + 5;
        }
    }

    return ReturnAddress != 0;
}

// See VirtualMAlloc::Get, VirtualMAlloc::Alloc
class VirtualMAlloc {
    DWORD processId = GetCurrentProcessId();
    DWORD_PTR baseAddress = ModUtils::GetProcessBaseAddress(GetCurrentProcessId());

private:
    SYSTEM_INFO sys;
    VirtualMAlloc()
    {
        GetSystemInfo(&sys);
        ModUtils::Log("Process base address: %p", baseAddress);
        ModUtils::Log("System page size: %u", sys.dwPageSize);
        ModUtils::Log("System allocation granularity: %u", sys.dwAllocationGranularity);
    };

public:
    // Get instance
    static VirtualMAlloc& Get()
    {
        static VirtualMAlloc instance;
        return instance;
    }

private:
    LPBYTE lpScan = 0;
    MEMORY_BASIC_INFORMATION memInfo;

    LPVOID lpCurrent = 0;
    DWORD bytesAllocated = 0;
    DWORD currentPageSize = 0;

    void Scan()
    {
        lpScan = lpScan ? lpScan : (LPBYTE)baseAddress;
        SIZE_T numBytes = VirtualQuery(lpScan, &memInfo, sizeof(memInfo));

        while (numBytes)
        {
            lpScan = static_cast<LPBYTE>(memInfo.BaseAddress);

            if (memInfo.State == MEM_FREE)
            {
                //ModUtils::Log("mem free: %p %p %u", memInfo.BaseAddress, memInfo.AllocationBase, memInfo.RegionSize);
                //lpFree = memInfo.BaseAddress;
                break;
            }

            lpScan -= sys.dwAllocationGranularity;
            numBytes = VirtualQuery(lpScan, &memInfo, sizeof(memInfo));
        }
    }
private:
    // ???

public:

    // Allocate memory below process base address
    // This allows for memory hooks using shorter jump ops (eg. 0xE9)
    // Subsequent calls usually access the same memory page
    // see VirtualAlloc function
    // 
    // dwSize in [1..4096]
    LPVOID Alloc(SIZE_T dwSize, DWORD flAllocType = MEM_RESERVE|MEM_COMMIT, DWORD flProtec = PAGE_EXECUTE_READWRITE)
    {
        if (dwSize > 0x1000)
        {
            return nullptr;
        }

        bytesAllocated += static_cast<DWORD>(dwSize);

        if (!lpCurrent || bytesAllocated > currentPageSize)
        {
            Scan();
            ModUtils::Log("Allocating page at: %p", lpScan);

            // Preallocate a region equals to system page size (typically 4KiB)
            // do I really need to free this later?
            ///idk i'm tired
            lpCurrent = VirtualAlloc(lpScan, sys.dwPageSize, flAllocType, flProtec);

            bytesAllocated = static_cast<DWORD>(dwSize);
            currentPageSize = static_cast<DWORD>(sys.dwPageSize);
        }

        return (LPBYTE)lpCurrent + bytesAllocated - dwSize;
    }
};

// Creates or removes a hook using a relative jump
// First jump to an intermediate address at which we then do an absolute jump to the custom code
// This way we don't have to determine the size of the custom asm
// We also copy the stolen bytes over to the intermediate location so the custom code can omit the original code
// can't hook where the rsp is used tho
class HookRelativeIntermediate
{
public:
    static const uint8_t op = 0xE8;
    static const unsigned char opSize = 5;

    // writes an absolute jump to destination at specified address (14 bytes)
    class HookAbsoluteNoCopy
    {
        static const uint16_t op = 0x25ff;

        LPVOID lpHook;
        LPVOID lpDest;

    public:
        void Enable()
        {
            if (lpHook && lpDest)
            {
                *static_cast<uint64_t*>(lpHook) = static_cast<uint64_t>(op);
                *reinterpret_cast<uint64_t*>(static_cast<uint8_t*>(lpHook) + 6) = reinterpret_cast<uint64_t>(lpDest);
            }
        }

        HookAbsoluteNoCopy(LPVOID lpHook = nullptr, LPVOID lpDestination = nullptr, size_t offset = 0) : lpDest(lpDestination)
        {
            this->lpHook = static_cast<LPBYTE>(lpHook) + offset;
        }
    };

private:
    LPVOID lpHook;
    LPVOID lpIntermediate;
    LPVOID lpDestination;
    size_t numBytes;

    bool bEnabled = false;
    HookAbsoluteNoCopy jmpAbs;

    // Initialize the intermediate code that we can decide to jump to later
    void Init() // feels brit'ish
    {
        lpIntermediate = VirtualMAlloc::Get().Alloc(numBytes + 14 + 4 + 4); // one 14B jump, two 3B adds

        // move stack pointer up so stolen instructions can access the stack
        ModUtils::MemCopy(uintptr_t(lpIntermediate), uintptr_t(espUp.data()), 4);

        // copy to be stolen bytes to the imtermediate location
        ModUtils::MemCopy(reinterpret_cast<uint64_t>(lpIntermediate) + 4, reinterpret_cast<uint64_t>(lpHook), numBytes);

        // move stack pointer down so the custom code can return
        ModUtils::MemCopy(uintptr_t(lpIntermediate) + 4 + numBytes, uintptr_t(espDown.data()), 4);

        // create jump from intermediate location after the original code to custom code
        jmpAbs = HookAbsoluteNoCopy(lpIntermediate, lpDestination, 4 + numBytes + 4);
        jmpAbs.Enable();

        ModUtils::Log("Generated hook from %p to %p at %p", lpHook, lpDestination, lpIntermediate);
    }

public:
    HookRelativeIntermediate(HookRelativeIntermediate&) = delete;
    HookRelativeIntermediate(LPVOID lpHook, LPVOID lpDestination, const size_t numStolenBytes)
        : numBytes(numStolenBytes), lpHook(lpHook), lpDestination(lpDestination)
    {
        Init();
    }
    HookRelativeIntermediate(const std::vector<BYTE>& signature, size_t numStolenBytes, LPVOID destination)
        : numBytes(numStolenBytes), lpDestination(destination)
    {
        lpHook = reinterpret_cast<LPVOID>(ModUtils::SigScan(std::vector<uint16_t>(signature.begin(), signature.end())));
        Init();
    }

    static const std::vector<uint8_t> espUp; // add esp, 8 (3B)
    static const std::vector<uint8_t> espDown; // add esp -8

    void Enable()
    {
        if (bEnabled) { return; }
        ModUtils::Log("Enabling hook from %p to %p", lpHook, lpDestination);

        // pad the jump in case numBytes > jump instruction size
        ModUtils::MemSet(reinterpret_cast<uintptr_t>(lpHook), 0x90, numBytes);

        // write instruction at hook address
        *static_cast<uint8_t*>(lpHook) = op;
        uint32_t relOffset = static_cast<uint32_t>(static_cast<uint8_t*>(lpIntermediate) - static_cast<uint8_t*>(lpHook) - opSize);
        *reinterpret_cast<uint32_t*>(static_cast<uint8_t*>(lpHook) + 1) = relOffset;
    }
    void Disable()
    {
        if (!bEnabled) { return; }
        ModUtils::Log("Disabling hook from %p to %p", lpHook, lpDestination);
        ModUtils::MemCopy(uintptr_t(lpHook), uintptr_t(lpIntermediate), numBytes);
    }
    ~HookRelativeIntermediate() { Disable(); }
};

const std::vector<uint8_t> HookRelativeIntermediate::espDown({ 0x48, 0x83, 0xC4, 0xF8 });
const std::vector<uint8_t> HookRelativeIntermediate::espUp({ 0x48, 0x83, 0xC4, 0x08 });

HookRelativeIntermediate HOOK_CAMERA_DISTANCE(
    std::vector<uint8_t>({ 0x48, 0x8D, 0x4C, 0x24, 0x20, 0x44, 0x0F, 0x28, 0xD8, 0xF3, 0x45, 0x0F, 0x59, 0xDF }),
    5,
    &CameraDistanceAlt
);

DWORD WINAPI MainThread(LPVOID lpParam)
{

    //MEMORY_BASIC_INFORMATION meminfo;
    //if (VirtualQuery((LPBYTE)baseAddress - 1, &meminfo, sizeof(meminfo)))
    //{
    //    ModUtils::Log("meminfo: %p %p %u %u %u", meminfo.BaseAddress, meminfo.AllocationBase, meminfo.RegionSize, meminfo.Type, meminfo.Protect);
    //}
    HOOK_CAMERA_DISTANCE.Enable();

    LoadConfig();
    //HookCameraDistance();

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

