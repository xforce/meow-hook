#include "meow_hook/detour.h"

#include <Zydis/Utils.h>
#include <Zydis/Zydis.h>
#include <asmjit/asmjit.h>

namespace meow_hook::detail
{
void detour_base::unhook()
{
    if (address_ > 0) {
        DWORD old_protect;
        VirtualProtect((LPVOID)address_, original_code_.size(), PAGE_EXECUTE_READWRITE,
                       &old_protect);
        memcpy((void*)address_, original_code_.data(), original_code_.size());
        VirtualProtect((LPVOID)address_, original_code_.size(), old_protect, &old_protect);
    }
    if (trampoline_) {
        VirtualFree(trampoline_, 0, MEM_RELEASE);
    }
}

void* detour_base::Allocate2GBRange(uintptr_t address, size_t dwSize)
{
    static uint32_t allocation_granularity = 0;
    if (allocation_granularity == 0) {
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        allocation_granularity = si.dwAllocationGranularity;
    }

    uintptr_t min;
    uintptr_t max;
    uintptr_t addr;
    uintptr_t add  = allocation_granularity - 1;
    uintptr_t mask = ~add;

    min = address >= 0x40000000 ? (address - 0x40000000 + add) & mask : 0;
    max = address < (std::numeric_limits<uintptr_t>::max() - 0x40000000)
              ? (address + 0x40000000) & mask
              : std::numeric_limits<uintptr_t>::max();

    ::MEMORY_BASIC_INFORMATION mbi;
    do {
        if (!VirtualQuery((void*)min, &mbi, sizeof(mbi))) {
            return nullptr;
        }

        min = (UINT_PTR)mbi.BaseAddress + mbi.RegionSize;

        if (mbi.State == MEM_FREE) {
            addr = ((UINT_PTR)mbi.BaseAddress + add) & mask;

            if (addr < min && dwSize <= (min - addr)) {
                if (addr = (uintptr_t)VirtualAlloc((void*)addr, dwSize, MEM_COMMIT | MEM_RESERVE,
                                                   PAGE_EXECUTE_READWRITE)) {
                    return (void*)addr;
                }
            }
        }

    } while (min < max);

    return nullptr;
}

} // namespace meow_hook::detail
