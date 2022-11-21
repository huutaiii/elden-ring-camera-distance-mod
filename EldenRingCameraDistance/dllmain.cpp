// dllmain.cpp : Defines the entry point for the DLL application.
#include "framework.h"
#include "resource.h"

#pragma warning(push, 0)
#include <vector>
#include <xmmintrin.h>
#include <iostream>
#include <fstream>
#include <functional>
#include <memory>
#include <queue>
#include <cmath>

#include <ModUtils.h>
#include <INIReader.h>
#include <glm/matrix.hpp>
#include <glm/gtx/transform.hpp>
#include <glm/gtx/string_cast.hpp>
#pragma warning(pop)

constexpr double PI = 3.14159265359;
constexpr unsigned int JMP_SIZE = 14;
constexpr bool AUTOENABLE = true;

#define USE_HOTKEYS 0
#define USE_TEST_PATTERNS 1
#define DISABLE_AUTO_ROTATION 0
unsigned int PIVOT_INTERP_DELAY = 0;
float PIVOT_INTERP_SPEED = 16.f;

HMODULE g_hModule;

extern "C"
{
    uintptr_t ReturnAddress;
    void CameraDistance();
    void CameraDistanceAlt();
    __m128 CameraDistanceMul;
    __m128 CameraDistanceAdd;

    void ModifyFoV();
    __m128 FoVMul;

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

    void PassPivotRotation();

    float* FrameTime;

    void TargetLockOffset();
    void SetTargetLockState();
}

glm::vec4 vec_from__m128(__m128 m)
{
    float v[4];
    _mm_storer_ps(v, m); // MSVC specific, keeps components in reverse order
    return glm::vec4(v[3], v[2], v[1], v[0]);
}

inline __m128 GLMToXMM(glm::vec3 v)
{
    return _mm_setr_ps(v.x, v.y, v.z, 0.f);
}

inline glm::vec4 XMMToGLM(__m128 m)
{
    float v[4];
    _mm_storer_ps(v, m); // MSVC specific, keeps components in reverse order
    return glm::vec4(v[3], v[2], v[1], v[0]);
}

inline float RelativeOffsetAlpha(glm::vec3 offset, float max_distance)
{
    return glm::length(offset) / max_distance;
}

template<typename T>
inline T min(T a, T b) { return a < b ? a : b; }

template<typename T>
inline T max(T a, T b) { return a > b ? a : b; }

// Clamps x to range [a..b]
template<typename T>
inline T clamp(T x, T a = 0.0, T b = 1.0) { return min(b,max(a,x)); }

template<typename Tv, typename Ta>
inline Tv lerp(Tv x, Tv y, Ta a) { return x * ((Ta)1.0 - a) + y * a; }

template<typename T>
inline T smoothstep(T edge0, T edge1, T x) {
    x = clamp((x - edge0) / (edge1 - edge0), (T)0, (T)1);
    return x * x * (3 - 2 * x);
}

template<typename T> T EaseInOutSine(T x) {
    return -(cos(PI * x) - 1) / 2;
}

inline glm::vec3 V3InterpTo(glm::vec3 current, glm::vec3 target, float speed = 1, float deltaTime = 1.f/60.f, float minDistance = 0.001f)
{
    if (speed <= 0.f)
    {
        return target;
    }

    glm::vec3 delta = (target - current);
    if (glm::length(delta) <= minDistance)
    {
        return target;
    }

    //glm::vec3 vel = delta * deltaTime * speed;
    //vel = glm::normalize(vel) * min(glm::length(vel), glm::length(delta));
    glm::vec3 vel = delta * clamp(deltaTime * speed, 0.f, 1.f);
    return current + vel;
}

glm::vec3 RelativeOffset;
glm::vec3 LockedonOffset;
std::queue<__m128> RelativeOffsetBuffer;
extern "C" __m128 OffsetInterp = _mm_setzero_ps();
extern "C" __m128 CollisionOffset = _mm_setzero_ps();
extern "C" __m128 TargetOffset = _mm_setzero_ps();
float OffsetScale = 0.f;

glm::vec3 LastOffset = { 0, 0, 0 };

uintptr_t AutoRotationAddress;
uintptr_t AutoRotationBytes;

extern "C"
{
    float PivotYaw = 0.f;
    __m128 pvResolvedOffset = _mm_setzero_ps();
    __m128 pvPivotPosition = _mm_setzero_ps();
    float fCamMaxDistance = 0.f;
    uint32_t bHasTargetLock = 0;
    __m128 pvTargetPosition = _mm_setzero_ps();
    
    void SetPivotYaw();
    void SetCameraCoords();
    void SetCameraMaxDistance();
    void PivotOffset();
    void CameraCollisionOffset();
    void CameraOffset();
    void CollisionEndOffset();

    // coord system is Z-forward Y-up
    __m128 CalcPivotOffset() // compiled code uses xmm0-5 (used to, maybe)
    {
#if 0
        //TODO: reduce offset based on collision
        glm::mat4x4 rotation = glm::rotate(PivotYaw, glm::vec3(0.f, 1.f, 0.f));
        float distance = RelativeOffsetAlpha(vec_from__m128(pvResolvedOffset), fCamMaxDistance) - OffsetScale;
        OffsetScale += distance;
        glm::vec4 vOffset = rotation * glm::vec4(RelativeOffset, 0.f) * OffsetScale;

        glm::vec3 vOffsetInterp = V3InterpTo(vec_from__m128(OffsetInterp), vOffset, PIVOT_INTERP_SPEED);
        __m128 offset = _mm_setr_ps(vOffsetInterp.x, vOffsetInterp.y, vOffsetInterp.z, 0.f);

        /*if (distance > 0.0)
        {
            ModUtils::MemSet(AutoRotationAddress, 0x90, 7);
        }
        else
        {
            ModUtils::MemCopy(AutoRotationAddress, AutoRotationBytes, 7);
        }*/

        if (PIVOT_INTERP_DELAY > 0)
        {
            std::queue<__m128>& buffer = RelativeOffsetBuffer;
            buffer.push(offset);
            if (buffer.size() >= PIVOT_INTERP_DELAY)
            {
                while (buffer.size() > PIVOT_INTERP_DELAY)
                {
                    buffer.pop();
                }
                CollisionOffset = buffer.front();
                buffer.pop();
            }
        }
        else
        {
            CollisionOffset = offset;
        }
        OffsetInterp = offset;

#endif
        return OffsetInterp;
    }

    void CalcCameraOffset()
    {
        float offsetScale = RelativeOffsetAlpha(vec_from__m128(pvResolvedOffset), fCamMaxDistance);
        glm::vec3 localOffset = bHasTargetLock ? LockedonOffset : RelativeOffset;

        glm::mat4x4 rotation = glm::rotate(PivotYaw, glm::vec3(0.f, 1.f, 0.f));
        glm::vec3 targetOffset = rotation * glm::vec4(localOffset, 0.f) * 1.f;
        glm::vec3 offset = V3InterpTo(LastOffset, targetOffset, PIVOT_INTERP_SPEED);
        float targetDistance = glm::length(glm::vec3(XMMToGLM(pvPivotPosition)) - glm::vec3(XMMToGLM(pvTargetPosition)));
        float targetOffsetScale = log(targetDistance);
        LastOffset = offset;
        OffsetInterp = GLMToXMM(offset * max(offsetScale - 1.f / targetDistance, -1.f));
        CollisionOffset = GLMToXMM(offset);
        TargetOffset = GLMToXMM(offset * offsetScale * targetOffsetScale);
        
        //_mm_setr_ps(offset.x, offset.y, offset.z, 0.f);
    }
}

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

struct SModConfig {
    bool bUseCameraDistance = false;
    bool bUsePivotSpeed = false;
    bool bUseFoV = false;
    bool bUseCameraOffset = false;
} ModConfig;

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
        ModUtils::Log("using distance multiplier = %f", multiplier);
        CameraDistanceMul = _mm_set_ss(multiplier);

        float offset = reader.GetFloat("camera_distance", "flat_offset", 0.f);
        ModUtils::Log("using offset = %f", offset);
        CameraDistanceAdd = _mm_set_ss(offset);

        ModConfig.bUseCameraDistance = multiplier != 1.f || offset != 0.f;

        float fovmul = reader.GetFloat("fov", "multiplier", 1.0f);
        ModUtils::Log("using fov multiplier = %f", fovmul);
        FoVMul = _mm_set_ss(fovmul);

        ModConfig.bUseFoV = fovmul != 1.f;

        float follow_speed_multiplier = reader.GetFloat("camera_interpolation", "follow_speed_multiplier", 1.f);
        float speed_mul_z = reader.GetFloat("camera_interpolation", "follow_speed_multiplier_z", 0.f);
        ModUtils::Log("using follow_speed_multiplier = %f", follow_speed_multiplier);
        ModUtils::Log("using follow_speed_multiplier_z = %f", speed_mul_z);
        InterpSpeedMul = _mm_set_ss(follow_speed_multiplier);
        vInterpSpeedMul = (speed_mul_z > 0.f) ? _mm_setr_ps(follow_speed_multiplier, speed_mul_z, follow_speed_multiplier, 0.f)
            : _mm_setr_ps(follow_speed_multiplier, follow_speed_multiplier, follow_speed_multiplier, 0.f);

        ModConfig.bUsePivotSpeed = follow_speed_multiplier != 1.f || speed_mul_z != 0.f;

        std::vector<float> relative_offset_val = reader.GetVector<3, float>("camera_offset", "offset", std::vector<float>(3, 0.f));
        glm::vec3 relative_offset(relative_offset_val[0], relative_offset_val[1], relative_offset_val[2]);
        ModUtils::Log("using relative_offset = %s", glm::to_string(relative_offset).c_str());
        RelativeOffset = relative_offset;

        std::vector<float> lockon_offset_val = reader.GetVector<3, float>("camera_offset", "lockon_offset", std::vector<float>(3, 0.f));
        LockedonOffset = glm::vec3(lockon_offset_val[0], lockon_offset_val[1], lockon_offset_val[2]);
        ModUtils::Log("using lockon_offset = %s", glm::to_string(LockedonOffset).c_str());

        ModConfig.bUseCameraOffset = glm::length(RelativeOffset) + glm::length(LockedonOffset) > 0.0001;
    }
}

#if 0
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
#endif

// See VirtualMAlloc::Get, VirtualMAlloc::Alloc
class MVirtualAlloc {
    DWORD processId = GetCurrentProcessId();
    DWORD_PTR baseAddress = ModUtils::GetProcessBaseAddress(GetCurrentProcessId());

private:
    SYSTEM_INFO sys;
    MVirtualAlloc()
    {
        GetSystemInfo(&sys);
        ModUtils::Log("Process base address: %p", baseAddress);
        ModUtils::Log("System page size: %u", sys.dwPageSize);
        ModUtils::Log("System allocation granularity: %u", sys.dwAllocationGranularity);
    };

public:
    // Get instance
    static MVirtualAlloc& Get()
    {
        static MVirtualAlloc instance;
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
            lpCurrent = VirtualAlloc(lpScan, sys.dwPageSize, flAllocType, flProtec);

            bytesAllocated = static_cast<DWORD>(dwSize);
            currentPageSize = static_cast<DWORD>(sys.dwPageSize);
        }

        return (LPBYTE)lpCurrent + bytesAllocated - dwSize;
    }

    // there's no deallocation 'cause we don't need it, for now
};

// Creates or removes a hook using a relative jump (5 bytes)
// First jump to an intermediate address at which we then do an absolute jump to the custom code
// This way we don't have to determine the size of the custom asm
// We also copy the stolen bytes over to the intermediate location so the custom code can omit the original code
class UHookRelativeIntermediate
{
public:
    static const uint8_t op = 0xE8;
    static const unsigned char opSize = 5;

    // writes an absolute jump to destination at specified address (14 bytes)
    class UHookAbsoluteNoCopy
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

        UHookAbsoluteNoCopy(LPVOID lpHook = nullptr, LPVOID lpDestination = nullptr, size_t offset = 0) : lpDest(lpDestination)
        {
            this->lpHook = static_cast<LPBYTE>(lpHook) + offset;
        }
    };

private:

    LPVOID lpHook = nullptr;
    LPVOID lpIntermediate = nullptr;
    LPVOID lpDestination = nullptr;
    size_t numBytes = 5;
    MVirtualAlloc& allocator = MVirtualAlloc::Get();

    bool bCanHook = false;
    bool bEnabled = false;
    std::unique_ptr<UHookAbsoluteNoCopy> upJmpAbs;

    // Initialize the intermediate code that we can decide to jump to later
    void Init()
    {
        lpIntermediate = allocator.Alloc(numBytes + 14 + rspUp.size() + rspDown.size()); // one 14B jump, two 3B adds

        // move stack pointer up so stolen instructions can access the stack
        ModUtils::MemCopy(uintptr_t(lpIntermediate), uintptr_t(rspUp.data()), rspUp.size());

        // copy to be stolen bytes to the imtermediate location
        ModUtils::MemCopy(reinterpret_cast<uint64_t>(lpIntermediate) + rspUp.size(), reinterpret_cast<uint64_t>(lpHook), numBytes);

        // move stack pointer down so the custom code can return
        ModUtils::MemCopy(uintptr_t(lpIntermediate) + rspUp.size() + numBytes, uintptr_t(rspDown.data()), rspDown.size());

        // create jump from intermediate code to custom code
        upJmpAbs = std::make_unique<UHookAbsoluteNoCopy>(lpIntermediate, lpDestination, rspUp.size() + numBytes + rspDown.size());
        upJmpAbs->Enable();

        ModUtils::Log("Generated hook '%s' from %p to %p at %p", msg.c_str(), lpHook, lpDestination, lpIntermediate);
    }

public:
    const std::string msg;

    UHookRelativeIntermediate(UHookRelativeIntermediate&) = delete;
    //UHookRelativeIntermediate(LPVOID lpHook, LPVOID lpDestination, const size_t numStolenBytes)
    //    : numBytes(numStolenBytes), bCanHook(true), lpHook(lpHook), lpDestination(lpDestination), msg({}), allocator(MVirtualAlloc::Get())
    //{
    //    Init();
    //}
    UHookRelativeIntermediate(
        std::vector<uint16_t> signature,
        size_t numStolenBytes,
        LPVOID destination,
        int offset = 0,
        std::string msg = "Unknown Hook",
        std::function<void()> enable = []() {},
        std::function<void()> disable = []() {}
    )
        : numBytes(numStolenBytes), lpDestination(destination), msg(msg), fnEnable(enable), fnDisable(disable)
    {
        lpHook = reinterpret_cast<LPVOID>(ModUtils::SigScan(signature, false, msg, true) + offset);
        bCanHook = lpHook != nullptr;
        //Init();
    }

    const bool HasFoundSignature() const { return bCanHook; }

    static const std::vector<uint8_t> rspUp; // lea rsp,[rsp+8] (5B)
    static const std::vector<uint8_t> rspDown; // lea rsp,[rsp-8] (5B)

    std::function<void()> fnEnable;
    std::function<void()> fnDisable;

    void Enable()
    {
        if (!lpIntermediate)
        {
            Init();
        }

        if (!bCanHook || bEnabled) { return; }
        ModUtils::Log("Enabling hook '%s' from %p to %p", msg.c_str(), lpHook, lpDestination);

        // pad the jump in case numBytes > jump instruction size
        ModUtils::MemSet(reinterpret_cast<uintptr_t>(lpHook), 0x90, numBytes);

        // write instruction at hook address
        *static_cast<uint8_t*>(lpHook) = op;
        uint32_t relOffset = static_cast<uint32_t>(static_cast<uint8_t*>(lpIntermediate) - static_cast<uint8_t*>(lpHook) - opSize);
        *reinterpret_cast<uint32_t*>(static_cast<uint8_t*>(lpHook) + 1) = relOffset;
        
        fnEnable();
        bEnabled = true;
    }
    void Disable()
    {
        if (!bEnabled) { return; }
        ModUtils::Log("Disabling hook '%s' from %p to %p", msg.c_str(), lpHook, lpDestination);
        ModUtils::MemCopy(uintptr_t(lpHook), uintptr_t(lpIntermediate) + rspUp.size(), numBytes);

        fnDisable();
        bEnabled = false;
    }
    void Toggle()
    {
        bEnabled ? Disable() : Enable();
    }
    ~UHookRelativeIntermediate() { Disable(); }
};

const std::vector<uint8_t> UHookRelativeIntermediate::rspUp({ 0x48, 0x8D, 0x64, 0x24, 0x08 });
const std::vector<uint8_t> UHookRelativeIntermediate::rspDown({ 0x48, 0x8D, 0x64, 0x24, 0xf8 });

static decltype(ModUtils::MASKED) MASK = ModUtils::MASKED;

//    |
//    v
//  48 8D 4C 24 20        - lea rcx,[rsp+20]
//  44 0F28 D8            - movaps xmm11,xmm0
//  F3 45 0F59 DF         - mulss xmm11,xmm15
//  E8 18BF9000           - call eldenring.exe+CC0870
//  48 8D 4C 24 20        - lea rcx,[rsp+20]
std::vector<uint16_t> PATTERN_DISTANCE = { 0x8D, MASK, MASK, MASK, MASK, 0x0F, 0x28, MASK, MASK, MASK, 0x0F, 0x59, MASK, 0xE8, MASK, MASK, MASK, MASK, MASK, 0x8D, MASK, 0x24, MASK };
UHookRelativeIntermediate HookCameraDistance(
    PATTERN_DISTANCE/*std::vector<uint16_t>({ 0x48, 0x8D, 0x4C, 0x24, 0x20, 0x44, 0x0F, 0x28, 0xD8, 0xF3, 0x45, 0x0F, 0x59, 0xDF })*/,
    5,
    &CameraDistanceAlt,
    -1,
    "HookCameraDistance"
);

//    |
//    v
//  44 0F28 00            - movaps xmm8,[rax]
//  0F28 C4               - movaps xmm0,xmm4
//  41 0F5C 21            - subps xmm4,[r9]
//  0F5C C6               - subps xmm0,xmm6
//  F3 0F5E DD            - divss xmm3,xmm5
//  44 0F59 C8            - mulps xmm9,xmm0
//  0F28 C2               - movaps xmm0,xmm2
//  0F28 CB               - movaps xmm1,xmm3
std::vector<uint16_t> PATTERN_PIVOT = { 0x0F, 0x28, MASK, 0x0F, 0x28, MASK, MASK, 0x0F, 0x5C, MASK, 0x0F, 0x5C, MASK, MASK, 0x0F, 0x5E, MASK, MASK, 0x0F, 0x59, MASK, 0x0F, 0x28, MASK, 0x0F, 0x28, MASK };
UHookRelativeIntermediate HookPivotInterp(
    PATTERN_PIVOT/*std::vector<uint16_t>({ 0x0F, 0x28, 0xC4, 0x41, 0x0F, 0x5C, 0x21, 0x0F, 0x5C, 0xC6, 0xF3, 0x0F, 0x5E, 0xDD })*/,
    7,
    &CamInterpAlt,
    -1,
    "HookPivotInterp"
);

// Thanks to uberhalit (uberhalit/EldenRingFpsUnlockAndMore) for the disassembly
//  80 BB 88040000 00       - cmp byte ptr [rbx+00000488],00
//  44 0F28 E0              - movaps xmm12, xmm0
//  F3 44 0F10 05 E22CE202  - movss xmm8, [eldenring.exe.rdata + 8D8678]
//  45 0F57 D2              - xorps xmm10, xmm10
//  F3 45 0F59 E7           - mulss xmm12, xmm15
std::vector<uint16_t> PATTERN_FOV = { 0x80, 0xBB, MASK, MASK, MASK, MASK, 0x00, MASK, 0x0F, 0x28, MASK, 0xF3, MASK, 0x0F, 0x10, MASK, MASK, MASK, MASK, MASK, MASK, 0x0F, 0x57, MASK, 0xF3, MASK, 0x0F, 0x59, MASK };
UHookRelativeIntermediate HookFoVMul(
    PATTERN_FOV,
    11,
    &ModifyFoV,
    0,
    "HookFoVMul"
);

#if USE_TEST_PATTERNS

std::vector<uint16_t> PATTERN_CAMERA_YAW = { 0xF3, 0x0F, 0x10, 0x8E, 0x50, 0x01, 0x00, 0x00, 0x48, 0x8D, 0x8C, 0x24, 0x90, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xF8, 0xE8, 0x9E, 0xC3, 0xFF, 0xFF, 0x48, 0x8D, 0x8C, 0x24, 0xD0, 0x00, 0x00, 0x00 };
UHookRelativeIntermediate HookStorePivotRotation(
    PATTERN_CAMERA_YAW/*std::vector<uint16_t>({ 0xF3, 0x44, 0x0F, 0x11, 0x45, 0xB7, 0x44, 0x0F, 0x29, 0x45, 0xC7, 0x76, 0x05 })*/,
    8,
    &SetPivotYaw,
    0,
    "HookStorePivotRotation"
);

UHookRelativeIntermediate HookStoreCameraCoords(
    std::vector<uint16_t>({ 0x0F, 0x28, 0xB4, 0x24, 0xA0, 0x02, 0x00, 0x00, 0x48, 0x81, 0xC4, 0xB0, 0x02, 0x00, 0x00, 0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, 0x5F, 0x5E, 0x5D, 0xC3 }),
    8,
    &SetCameraCoords,
    0,
    "HookStoreCameraCoords"
);

std::vector<uint16_t> PATTERN_CAMERA_MAX_DISTANCE_INTERP({ 0xEB, 0x1C, 0xF3, 0x0F, 0x10, 0x83, 0xB8, 0x01, 0x00, 0x00, 0xF3, 0x0F, 0x5C, 0xF8, 0xF3, 0x0F, 0x59, 0xFE, 0xF3, 0x0F, 0x58, 0xF8, 0xF3, 0x0F, 0x11, 0xBB, 0xB8, 0x01, 0x00, 0x00 });
UHookRelativeIntermediate HookStoreCameraMaxDistance(
    PATTERN_CAMERA_MAX_DISTANCE_INTERP,
    8,
    &SetCameraMaxDistance,
    int(PATTERN_CAMERA_MAX_DISTANCE_INTERP.size() - 8),
    "HookStoreCameraMaxDistance"
);

uintptr_t HookOffsetInterp;
LPVOID HookOffsetInterpBytes;
void HookPivotOffsetEnable()
{
    // force update pivot location when pushing right stick
    /*std::vector<uint16_t> pattern({ 0x0F, 0x8A, 0x86, 0x00, 0x00, 0x00, 0x0F, 0x85, 0x80, 0x00, 0x00, 0x00, 0x44, 0x0F, 0x59, 0x83, 0x70, 0x02, 0x00, 0x00, 0x48, 0x8D, 0xBB, 0x58, 0x02, 0x00, 0x00, 0x48, 0x8D, 0xB3, 0x5C, 0x02, 0x00, 0x00 });
    HookOffsetInterp = ModUtils::SigScan(pattern);
    if (HookOffsetInterp)
    {
        HookOffsetInterpBytes = MVirtualAlloc::Get().Alloc(12);
        ModUtils::MemCopy(uintptr_t(HookOffsetInterpBytes), HookOffsetInterp, 12);
        ModUtils::MemSet(HookOffsetInterp, 0x90, 12);
    }*/

#if DISABLE_AUTO_ROTATION
    AutoRotationAddress = ModUtils::SigScan({ 0x0F, 0x29, 0xA6, 0x50, 0x01, 0x00, 0x00, 0x41, 0x0F, 0x28, 0xCF, 0x48, 0x8B, 0xCE, 0xE8, 0xC2, 0x2F, 0x00, 0x00, 0x44, 0x0F, 0xB6, 0x44, 0x24, 0x30 });
    if (AutoRotationAddress)
    {
        AutoRotationBytes = (uintptr_t)MVirtualAlloc::Get().Alloc(7);
        //ModUtils::MemCopy(AutoRotationBytes, AutoRotationAddress, 7);
        ModUtils::MemSet(AutoRotationAddress, 0x90, 7);
    }

    uintptr_t WobbleAddress = ModUtils::SigScan({ 0xF3, 0x0F, 0x11, 0x81, 0x44, 0x01, 0x00, 0x00, 0x76, 0x06, 0x89, 0xB9, 0x44, 0x01, 0x00, 0x00, 0x0F, 0x2F, 0xB9, 0x44, 0x01, 0x00, 0x00, 0x72, 0x2B, 0xF3, 0x0F, 0x10, 0x89, 0x40, 0x01, 0x00, 0x00 });
    if (WobbleAddress)
    {
        ModUtils::MemSet(WobbleAddress, 0x90, 8);
    }

    uintptr_t ForceInterpAddress = ModUtils::SigScan({ 0x0F, 0x84, 0xC3, 0x00, 0x00, 0x00, 0x0F, 0x28, 0x65, 0xD0, 0x0F, 0x28, 0xD4, 0x0F, 0x59, 0xD4, 0x0F, 0x28, 0xCA, 0x0F, 0xC6, 0xCA, 0x66, 0xF3, 0x0F, 0x58, 0xD1, 0x0F, 0x28, 0xC1 });
    if (ForceInterpAddress)
    {
        const char* code = "\x90\xE9";
        ModUtils::MemCopy(ForceInterpAddress, (uintptr_t)code, 2);
    }
#endif
}

void HookPivotOffsetDisable()
{
    if (HookOffsetInterp && HookOffsetInterpBytes)
    {
        ModUtils::MemCopy(HookOffsetInterp, uintptr_t(HookOffsetInterpBytes), 12);
    }
}

std::vector<uint16_t> PATTERN_PIVOT_OFFSET({ 0x0F, 0x59, 0xA3, 0x90, 0x00, 0x00, 0x00, 0x0F, 0x58, 0xEC, 0x0F, 0x29, 0xAB, 0xC0, 0x00, 0x00, 0x00, 0x0F, 0x29, 0xAB, 0xD0, 0x00, 0x00, 0x00, 0x0F, 0x29, 0xAB, 0xE0, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x4D, 0xE0, 0x48, 0x33, 0xCC });
UHookRelativeIntermediate HookPivotOffset(
    PATTERN_PIVOT_OFFSET,
    10,
    &PivotOffset,
    0,
    "HookPivotOffset",
    HookPivotOffsetEnable,
    HookPivotOffsetDisable
);

std::vector<uint16_t> PATTERN_CAMERA_OFFSET({ 0x0F, 0x29, 0x87, 0x40, 0x04, 0x00, 0x00, 0x0F, 0x29, 0x8F, 0x50, 0x04, 0x00, 0x00, 0x48, 0x83, 0x3D, 0x09, 0xC4, 0x89, 0x03, 0x00, 0x48, 0x89, 0xAC, 0x24, 0x20, 0x01, 0x00, 0x00, 0x75, 0x27 });
UHookRelativeIntermediate HookCameraOffset(
    PATTERN_CAMERA_OFFSET,
    7,
    &CameraOffset,
    0,
    "HookCameraOffset",
    HookPivotOffsetEnable,
    HookPivotOffsetDisable
);

UHookRelativeIntermediate HookPivotOffsetAlt(
    std::vector<uint16_t>({ 0x66, 0x0F, 0x6F, 0x74, 0x24, 0x70, 0xE8, 0x3F, 0x85, 0x2A, 0x00, 0x85, 0xC0, 0x78, 0x56 }),
    6,
    &PivotOffset,
    0,
    "HookPivotOffsetAlt",
    HookPivotOffsetEnable,
    HookPivotOffsetDisable
);

//std::vector<uint16_t> PATTERN_COLLISION({ 0x48, 0x8B, 0x44, 0x24, 0x38, 0x0F, 0x58, 0x00, 0x0F, 0x29, 0x44, 0x24, 0x40, 0x48, 0x8D, 0x54, 0x24, 0x40, 0x48, 0x8D, 0x4D, 0x00, 0xE8, 0x54, 0xB1, 0x18, 0x00 });
std::vector<uint16_t> PATTERN_COLLISION({ 0x0F, 0x28, 0x4D, 0x00, 0x0F, 0x28, 0x6D, 0x10, 0x0F, 0x5C, 0xCD, 0x0F, 0x28, 0xC1, 0x0F, 0x15, 0x05, 0x3B, 0x28, 0xEC, 0x02, 0x0F, 0xC6, 0xC8, 0xC4 });
UHookRelativeIntermediate HookCollisionOffset(
    PATTERN_COLLISION,
    8,
    &CameraCollisionOffset,
    0,
    "HookCollisionOffset"
);

//std::vector<uint16_t> PATTERN_COLLISION_END({ 0x0F, 0x54, 0xCC, 0x0F, 0x56, 0xC8, 0x0F, 0x29, 0x5D, 0xA0, 0x0F, 0x29, 0x4D, 0xB0, 0x0F, 0x29, 0x6D, 0x90, 0x48, 0x8B, 0x05, 0xED, 0xDC, 0x05, 0x03 });
std::vector<uint16_t> PATTERN_COLLISION_END({ 0x48, 0x8B, 0x44, 0x24, 0x38, 0x0F, 0x58, 0x00, 0x0F, 0x29, 0x44, 0x24, 0x40, 0x48, 0x8D, 0x54, 0x24, 0x40, 0x48, 0x8D, 0x4D, 0x00, 0xE8, 0x54, 0xB1, 0x18, 0x00 });
UHookRelativeIntermediate HookCollisionEndOffset(
    PATTERN_COLLISION_END,
    8,
    &CollisionEndOffset,
    0,
    "HookCollisionEndOffset"
);

extern "C" uint32_t bDoLockTargetOffset = 0;
std::vector<uint16_t> PATTERN_LOCKON_OFFSET = { 0x44, 0x88, 0xA9, 0x12, 0x03, 0x00, 0x00, 0x0F, 0x28, 0x00, 0x66, 0x0F, 0x7F, 0x81, 0xF0, 0x02, 0x00, 0x00, 0x0F, 0x28, 0x0B, 0x66, 0x0F, 0x7F, 0x89, 0x00, 0x03, 0x00, 0x00, 0xC6, 0x87, 0x20, 0x11, 0x00, 0x00, 0x00, 0x80, 0xBF, 0x21, 0x11, 0x00, 0x00, 0x00 };
UHookRelativeIntermediate HookTargetLockOffset(
    PATTERN_LOCKON_OFFSET,
    10,
    &TargetLockOffset,
    0,
    "HookTargetLockOffset"
);

std::vector<uint16_t> PATTERN_LOCKON_STATE = { 0x80, 0xBE, 0x30, 0x28, 0x00, 0x00, 0x00, 0x0F, 0x84, 0x51, 0x01, 0x00, 0x00, 0x48, 0x85, 0xFF, 0x0F, 0x84, 0x15, 0x01, 0x00, 0x00, 0x80, 0xBE, 0x8C, 0x29, 0x00, 0x00, 0x00 };
UHookRelativeIntermediate HookTargetLockState(
    PATTERN_LOCKON_STATE,
    7,
    &SetTargetLockState,
    0,
    "HookTargetLockState"
);

#endif // if USE_TEST_PATTERNS

#pragma warning(suppress:4100) // unused param
DWORD WINAPI MainThread(LPVOID lpParam)
{
    //MEMORY_BASIC_INFORMATION meminfo;
    //if (VirtualQuery((LPBYTE)baseAddress - 1, &meminfo, sizeof(meminfo)))
    //{
    //    ModUtils::Log("meminfo: %p %p %u %u %u", meminfo.BaseAddress, meminfo.AllocationBase, meminfo.RegionSize, meminfo.Type, meminfo.Protect);
    //}
    LoadConfig();
    //HookCameraDistance.Enable();
    //HookPivotInterp.Enable();
    //HookFoVMul.Enable();

    std::vector <std::reference_wrapper<UHookRelativeIntermediate>> hooks;

    auto addHookIf = [&hooks](UHookRelativeIntermediate& hook, bool condition)
    {
        if (condition) {
            hooks.push_back(hook);
        }
    };

    addHookIf(HookCameraDistance, ModConfig.bUseCameraDistance);
    addHookIf(HookPivotInterp, ModConfig.bUsePivotSpeed);
    addHookIf(HookFoVMul, ModConfig.bUseFoV);

#if USE_TEST_PATTERNS
    if (ModConfig.bUseCameraOffset)
    {
        hooks.insert(hooks.end(), {
            HookStorePivotRotation,
            HookStoreCameraCoords,
            HookStoreCameraMaxDistance,
            HookCameraOffset,
            HookCollisionEndOffset,
            HookTargetLockOffset,
            HookTargetLockState,
            //HookCollisionOffset,
        });
    }
#endif

    for (UHookRelativeIntermediate& hook : hooks)
    {
        if (!hook.HasFoundSignature())
        {
            ModUtils::RaiseError("Failed to setup hook: " + hook.msg);
        }
    }

    if constexpr(AUTOENABLE)
    {
        for (UHookRelativeIntermediate& hook : hooks)
        {
            hook.Enable();
        }
    }

#if USE_HOTKEYS
    while (true)
    {
        if (ModUtils::CheckHotkey(0x70/*F1*/))
        {
            for (UHookRelativeIntermediate& hook : hooks)
            {
                hook.Toggle();
            }
        }
        Sleep(2);
    }
#endif
    //HookCameraDistance();

#if 0
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
#endif

    ModUtils::CloseLog();
    return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
#pragma warning(suppress:4100) // unused param
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

