#include "meow_hook/pattern_search.h"

#include <Windows.h>
#include <intrin.h>
#include <xmmintrin.h>

#include <algorithm>
#include <future>
#include <locale>
#include <vector>

namespace meow_hook
{
//

namespace
{
    class PESectionInfo
    {
      private:
        uintptr_t begin_;
        uintptr_t end_;

      public:
        decltype(auto) begin()
        {
            return begin_;
        }
        decltype(auto) end()
        {
            return end_;
        }

        PESectionInfo(uintptr_t begin, uintptr_t end)
            : begin_(begin)
            , end_(end)
        {
        }
    };

    static std::vector<PESectionInfo> GetExecutableSections()
    {
        std::vector<PESectionInfo> sections;

        auto executable_address = GetModuleHandle(NULL);

        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)(executable_address);
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            throw std::runtime_error("Invalid DOS Signature");
        }

        PIMAGE_NT_HEADERS header = (PIMAGE_NT_HEADERS)(
            ((char *)executable_address + (dosHeader->e_lfanew * sizeof(char))));
        if (header->Signature != IMAGE_NT_SIGNATURE) {
            throw std::runtime_error("Invalid NT Signature");
        }

        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(header);

        for (int32_t i = 0; i < header->FileHeader.NumberOfSections; i++, section++) {
            bool executable = (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
            bool readable   = (section->Characteristics & IMAGE_SCN_MEM_READ) != 0;
            if (readable && executable) {
                auto     beg        = ((uintptr_t)executable_address + section->VirtualAddress);
                uint32_t sizeOfData = std::min(section->SizeOfRawData, section->Misc.VirtualSize);
                sections.emplace_back(beg, beg + sizeOfData);
            }
        }
        return sections;
    }
} // namespace

static void generate_mask_and_data(std::string_view pattern, std::string &mask, std::string &data)
{
    const static std::locale loc;

    mask = "";
    data = "";

    for (auto &&ch = pattern.begin(); ch != pattern.end(); ++ch) {
        if (*ch == '?') {
            data += '\x00';
            mask += '?';
        } else if (std::isalnum(*ch, loc)) {
            auto ch1   = *ch;
            auto ch2   = *(++ch);
            char str[] = {ch1, ch2};
            char digit = static_cast<char>(strtol(str, nullptr, 16));
            data += digit;
            mask += 'x';
        }
    }
}

pattern::pattern(std::string pattern, std::optional<std::string_view> search_buffer)
    : search_buffer_(search_buffer)
{
    generate_mask_and_data(pattern, mask_, bytes_);
}

pattern::pattern(std::string_view pattern, std::optional<std::string_view> search_buffer)
    : search_buffer_(search_buffer)
{
    generate_mask_and_data(pattern, mask_, bytes_);
}

pattern::match pattern::get(int index)
{
    find_matches();
    return matches_[index];
}

size_t pattern::size()
{
    //
    find_matches();

    return matches_.size();
}

pattern &pattern::count(int expected)
{
    //
    find_matches();

    if (matches_.size() != expected) {
        throw std::runtime_error("Matches does not match expected");
    }
    return *this;
}

bool pattern::matches()
{
    find_matches();

    if (matches_.size() > 0) {
        return true;
    }
    return false;
}

void pattern::save_hints()
{
    //
}

bool pattern::load_hints()
{
    //
    return false;
}

void pattern::find_matches()
{
    if (matched_) {
        return;
    } else {
        matched_ = true;
    }

    //
    auto get_search_sections = [this]() {
        if (this->search_buffer_) {
            std::vector<PESectionInfo> sections;
            sections.emplace_back(reinterpret_cast<uintptr_t>(this->search_buffer_->data()),
                                  reinterpret_cast<uintptr_t>(this->search_buffer_->data() + this->search_buffer_->size()));
            return sections;
        }
        return GetExecutableSections();
    };

    auto does_match = [this](uintptr_t offset) {
        char *ptr = reinterpret_cast<char *>(offset);

        for (size_t i = 0; i < mask_.size(); i++) {
            if (mask_[i] == '?') {
                continue;
            }

            if (bytes_.length() < i || bytes_[i] != ptr[i]) {
                return false;
            }
        }

        return true;
    };

    if (load_hints()) {
        // Make sure we still match those
        bool all_match = true;
        for (auto &match : matches_) {
            if (!does_match(reinterpret_cast<uintptr_t>(match.get<uintptr_t>()))) {
                all_match = false;
                break;
            }
        }
        if (all_match) {
            // This ensures the pattern is in the cache
            // this is required when we try to get the same pattern again at a later time
            save_hints();
            return;
        }
        matches_.clear();
    }

    std::vector<std::future<std::vector<match>>> futureHandles = {};

    // check if SSE 4.2 is supported
    int32_t cpuid[4];
    __cpuid(cpuid, 0);
    bool sse42 = false;
    if (cpuid[0] >= 1) {
        __cpuidex(cpuid, 1, 0);

        sse42 = (cpuid[2] & (1 << 20));
    }

    bool sinlge_threaded = false;
    auto exe_sections = get_search_sections();
    if (sinlge_threaded) {
        for (auto &section : exe_sections) {
            auto section_size = section.end() - section.begin();
            if (section_size > 1) {
                std::vector<match> matches;
                for (uintptr_t offset = section.begin(); offset < section.end(); ++offset) {
                    if (does_match(offset)) {
                        matches.emplace_back(offset);
                    }
                }

                if (!matches.empty()) {
                    matches_.insert(matches_.end(), matches.begin(), matches.end());
                }
            }
        }
    } else  if (!sse42) {
        for (auto &section : exe_sections) {
            auto section_size = section.end() - section.begin();
            if (section_size > 1) {
                auto part_size = section_size / (std::thread::hardware_concurrency() / 2);
                auto rest      = section_size % part_size;
                for (uintptr_t i = section.begin(); i < section.end() - rest; i += part_size) {
                    auto handle = std::async(
                        std::launch::async,
                        [&](uintptr_t start, uintptr_t end) -> std::vector<match> {
                            std::vector<match> matches;
                            for (uintptr_t offset = start; offset < end; ++offset) {
                                if (does_match(offset)) {
                                    matches.emplace_back(offset);
                                }
                            }
                            return matches;
                        },
                        i, i + part_size);

                    futureHandles.push_back(std::move(handle));
                }
            }
        }
    } else {
        // SSE
        __declspec(align(16)) char desired_mask[16] = {0};

        const auto mask_size = std::min(mask_.size(), size_t(16));
        const auto data_size = std::min(bytes_.size(), size_t(16));
        for (int32_t i = 0; i < mask_size; i++) {
            desired_mask[i / 8] |= ((mask_[i] == '?') ? 0 : 1) << (i % 8);
        }

        __m128i mask      = _mm_load_si128(reinterpret_cast<const __m128i *>(desired_mask));
        __m128i comparand = _mm_loadu_si128(reinterpret_cast<const __m128i *>(bytes_.c_str()));

        for (auto &section : exe_sections) {
            const auto section_size = section.end() - section.begin();

            const auto part_size = section_size / (std::thread::hardware_concurrency() / 2);
            const auto rest      = section_size % part_size;
            for (uintptr_t i = section.begin(); i < (section.end() - rest); i += part_size) {
                auto _end = i + part_size;

                if (_end > (section.end() - 16)) {
                    _end = section.end() - 16;
                }
                auto handle = std::async(
                    std::launch::async,
                    [&](uintptr_t start, uintptr_t end) -> std::vector<match> {
                        std::vector<match> vmatches;
                        for (uintptr_t offset = start; offset < end; ++offset) {
                            __m128i value =
                                _mm_loadu_si128(reinterpret_cast<const __m128i *>(offset));
                            __m128i result =
                                _mm_cmpestrm(value, 16, comparand, static_cast<int>(data_size),
                                             _SIDD_CMP_EQUAL_EACH);

                            // as the result can match more bits than the mask contains
                            __m128i matches     = _mm_and_si128(mask, result);
                            __m128i equivalence = _mm_xor_si128(mask, matches);

                            if (_mm_test_all_zeros(equivalence, equivalence)) {
                                // Because we might only do partial match, make sure we actually
                                // have a full match
                                if (does_match(offset)) {
                                    vmatches.emplace_back(offset);
                                }
                            }
                        }
                        return vmatches;
                    },
                    i, _end);

                futureHandles.push_back(std::move(handle));
            }
        }
    }

    for (auto &handle : futureHandles) {
        auto matches = handle.get();

        if (!matches.empty()) {
            matches_.insert(matches_.end(), matches.begin(), matches.end());
        }
    }

    // Remove duplicates
    auto end = matches_.end();
    for (auto it = matches_.begin(); it != end; ++it) {
        end = std::remove(it + 1, end, *it);
    }
    matches_.erase(end, matches_.end());

    save_hints();
}

} // namespace meow_hook
