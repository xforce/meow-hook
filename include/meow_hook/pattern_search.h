#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <optional>

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

        void rebase(uintptr_t old_base, uintptr_t new_base) {
            pointer_ -= old_base;
            pointer_ += new_base;
        }

        match adjust(intptr_t val)
        {
            return match{pointer_ + val};
        }

        template <typename T = int32_t> match add_disp()
        {
            return match{pointer_ + *reinterpret_cast<T*>(pointer_)};
        }

        uintptr_t extract_call()
        {
            return pointer_ + *(int32_t*)(pointer_ + 1) + 5;
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

        bool operator<(const match& r) const
        {
            return (pointer_ < r.pointer_);
        }

        bool operator>(const match& r) const
        {
            return (pointer_ > r.pointer_);
        }

      private:
        uintptr_t pointer_ = 0;
    };

    template <size_t Len>
    pattern(const char (&pattern)[Len],  std::optional<std::string_view> search_buffer = {})
        : pattern(std::string_view(pattern, Len), search_buffer)
    {
    }
    explicit pattern(std::string pattern, std::optional<std::string_view> search_buffer = {});
    explicit pattern(std::string_view pattern, std::optional<std::string_view> search_buffer = {});

    match    get(int index);
    size_t   size();
    pattern& count(int expected);
    bool     matches();

  private:
    void save_hints();
    bool load_hints();
    void find_matches();

    bool               matched_ = false;
    std::string        bytes_ = "";
    std::string        mask_ = "";
    std::vector<match> matches_ = {};
    std::optional<std::string_view> search_buffer_ = {};
};
} // namespace meow_hook
