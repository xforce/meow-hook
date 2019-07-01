#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace meow_hook
{
class pattern
{
  public:
    class match
    {
      public:
        explicit match(uintptr_t pointer)
        {
            pointer_ = pointer;
        }

        uintptr_t addr()
        {
            return pointer_;
        }

        match adjust(intptr_t val)
        {
            return match{pointer_ + val};
        }

        template <typename T = int32_t> match add_disp()
        {
            return {pointer_ + *reinterpret_cast<T*>(pointer_)};
        }

        template <typename T = void> auto get(int offset = 0) -> T*
        {
            return reinterpret_cast<T*>(pointer_ + offset);
        }

        template <typename T> auto as() -> T
        {
            return static_cast<T>(pointer_);
        }

        bool operator==(const match& rhs) const
        {
            return pointer_ == rhs.pointer_;
        }

      private:
        uintptr_t pointer_;
    };

    template <size_t Len>
    pattern(const char (&pattern)[Len])
        : pattern(std::string_view(pattern, Len))
    {
    }
    explicit pattern(std::string pattern);
    explicit pattern(std::string_view pattern);

    match    get(int index);
    size_t   size();
    pattern& count(int expected);

  private:
    void save_hints();
    bool load_hints();
    void find_matches();

    bool               matched_;
    std::string        bytes_;
    std::string        mask_;
    std::vector<match> matches_;
};
} // namespace meow_hook
