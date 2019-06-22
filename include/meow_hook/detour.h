#pragma once

#include <cstdint>

namespace meow_hook
{

namespace detail
{
    template <class T> class detour;

    template <typename Ret, typename... Args> //
    class detour<Ret(Args...)>;

    class detour_base
    {
      public:
        detour_base(uintptr_t address, void *func)
            : address_(address)
            , function_(func)
        {
            //
        }
        virtual ~detour_base() = default;

      private:
        void hook();
        void unhook();

        uintptr_t address_  = 0;
        void *    function_ = nullptr;

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
    };

} // namespace detail

template <typename T> using detour = detail::detour<T>;
} // namespace meow_hook
