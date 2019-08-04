#pragma once

#include <cstdint>

namespace meow_hook
{
namespace detail
{
}

struct mem_protect {
    enum protection : uint32_t { READ = 1 << 1, WRITE = 1 << 2, EXECUTE = 1 << 3 };

    mem_protect(uintptr_t address, size_t size, uint32_t protection);
    ~mem_protect();

#if _WIN32
    uint32_t old_protect_;
#endif

    const uintptr_t address_;
    const size_t    size_;
};

template <typename T> void put(uintptr_t address, T val)
{
    //
    mem_protect p(address, sizeof(val), mem_protect::WRITE);
    *(T *)(address) = val;
}
} // namespace meow_hook
