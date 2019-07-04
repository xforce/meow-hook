#pragma once

#include <cstdint>
#include <vector>

namespace meow_hook
{

namespace detail
{
    template <class T> class detour;

    template <typename Ret, typename... Args> //
    class detour<Ret(Args...)>;

    class detour_base
    {
      protected:
        detour_base(uintptr_t address, void *func)
            : address_(address)
            , function_(func)
        {
            //
        }
        virtual ~detour_base() = default;

        inline auto trampoline_raw() const
        {
            return trampoline_;
        }

      private:
        void hook();
        void unhook();

        std::vector<uint8_t> create_absolute_jump() const;

        void *Allocate2GBRange(uintptr_t address, size_t dwSize);

        uintptr_t            address_    = 0;
        void *               function_   = nullptr;
        void *               trampoline_ = nullptr;
        std::vector<uint8_t> original_code_;

        template <class T> friend class detour;
    };

    template <typename Ret, typename... Args> //
    class detour<Ret(Args...)> : public detour_base
    {
      public:
        using function_t = Ret(Args...);

        //
        detour(uintptr_t address, function_t *fn)
            : detour_base(address, fn)
        {
            // Hook
            detour_base::hook();
        }

        ~detour() override
        {
            // Unhook
            detour_base::unhook();
        }

        inline function_t *trampoline() const
        {
            return (function_t *)(trampoline_raw());
        }
    };

} // namespace detail

template <typename T> using detour = detail::detour<T>;

// From:
// http://stackoverflow.com/questions/1082192/how-to-generate-random-variable-names-in-c-using-macros/17624752#17624752
//
#define MH_PP_CAT(a, b) MH_PP_CAT_I(a, b)
#define MH_PP_CAT_I(a, b) MH_PP_CAT_II(~, a##b)
#define MH_PP_CAT_II(p, res) res

#define MH_STATIC_DETOOUR_IMPL(n, addr, fn)                                                        \
    (([]() -> auto {                                                                               \
        static ::meow_hook::detour<decltype(fn)> n{addr, fn};                                      \
        return n.trampoline();                                                                     \
    })())

#define MH_STATIC_DETOUR(addr, fn)                                                                 \
    MH_STATIC_DETOOUR_IMPL(MH_PP_CAT(mh_detour, __COUNTER__), addr, fn)

} // namespace meow_hook
