#include "meow_hook/memory.h"

#if _WIN32
#include <Windows.h>
#endif

namespace meow_hook
{
#if _WIN32
namespace
{
    DWORD protection_to_win32(uint32_t protection)
    {
        if (protection == 0) {
            return PAGE_NOACCESS;
        }
        if (protection == mem_protect::protection::EXECUTE) {
            return PAGE_EXECUTE;
        }
        if (protection == mem_protect::protection::READ) {
            return PAGE_READONLY;
        }
        if (protection == mem_protect::protection::WRITE) {
            return PAGE_READWRITE;
        }
        if (protection & mem_protect::protection::WRITE
            && protection & mem_protect::protection::EXECUTE) {
            return PAGE_EXECUTE_READWRITE;
        }
        if (protection & mem_protect::protection::READ
            && protection & mem_protect::protection::EXECUTE) {
            return PAGE_EXECUTE_READ;
        }
        throw "meow";
    }
} // namespace
#endif

mem_protect::mem_protect(uintptr_t address, size_t size, uint32_t protection)
    : address_(address)
    , size_(size)
{
#if _WIN32
    VirtualProtect((LPVOID)address_, size_, protection_to_win32(protection), (PDWORD)&old_protect_);
#endif
}

mem_protect::~mem_protect()
{
#if _WIN32
    VirtualProtect((LPVOID)address_, size_, old_protect_, (PDWORD)&old_protect_);
#endif
}
} // namespace meow_hook
