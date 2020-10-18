#include "meow_hook/pattern_search.h"

#include <Windows.h>
#include <intrin.h>
#include <xmmintrin.h>

#include <algorithm>
#include <future>
#include <locale>
#include <tuple>
#include <vector>

namespace meow_hook
{
//
static std::unordered_map<std::string, std::vector<uintptr_t>>
find_matches(std::vector<std::tuple<std::string, std::string>> patterns,
             std::optional<std::string_view>                   search_buffer);

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

    auto res = ::meow_hook::find_matches({{
                                  this->mask_,
                                  this->bytes_,
                              }},
                              this->search_buffer_);
    if (res[this->mask_].size() == 0) {
        printf("Failed to find match :(\n");
    }
    for (auto n : res[this->mask_]) {
        this->matches_.emplace_back(n);
    }
}

static bool load_hints(std::unordered_map<std::string, std::vector<uintptr_t>> &matches)
{
    return false;
}

static void save_hints(std::unordered_map<std::string, std::vector<uintptr_t>> matches) {
    //
}

uint32_t __inline ctz(uint32_t value)
{
    DWORD trailing_zero = 0;

    if (_BitScanForward(&trailing_zero, value)) {
        return trailing_zero;
    } else {
        // This is undefined, I better choose 32 than 0
        return 32;
    }
}


static std::unordered_map<std::string, std::vector<uintptr_t>>
find_matches(std::vector<std::tuple<std::string, std::string>> patterns,
             std::optional<std::string_view>                   search_buffer)
{
    std::unordered_map<std::string, std::vector<uintptr_t>> matches;
    //
    auto get_search_sections = [&]() {
        if (search_buffer) {
            std::vector<PESectionInfo> sections;
            sections.emplace_back(
                reinterpret_cast<uintptr_t>(search_buffer->data()),
                reinterpret_cast<uintptr_t>(search_buffer->data() + search_buffer->size()));
            return sections;
        }
        return GetExecutableSections();
    };

    auto does_match = [](std::tuple<std::string, std::string> pattern, uintptr_t offset) {
        auto &[mask, bytes] = pattern;
        char *ptr            = reinterpret_cast<char *>(offset);

        for (size_t i = 0; i < mask.size(); i++) {
            if (mask[i] == '?') {
                continue;
            }

            if (bytes.length() < i || bytes[i] != ptr[i]) {
                return false;
            }
        }

        return true;
    };

    if (load_hints(matches)) {
         // Make sure we still match those
         //bool all_match = true;
         //for (auto &match : matches) {
         //   if (!does_match(reinterpret_cast<uintptr_t>(match.get<uintptr_t>()))) {
         //       all_match = false;
         //       break;
         //   }
         //}
         //if (all_match) {
         //   // This ensures the pattern is in the cache
         //   // this is required when we try to get the same pattern again at a later time
         //   save_hints(matches);
         //   return;
         //}
         //matches_.clear();
    }

    // check if SSE 4.2 is supported
    int32_t cpuid[4];
    __cpuid(cpuid, 0);
    bool sse42new = false;
    bool sse42old = true;
    bool avx   = false;
    if (cpuid[0] >= 1) {
        __cpuidex(cpuid, 1, 0);

        sse42new = (cpuid[2] & (1 << 20));
        avx = (cpuid[2] & (1 << 28));
    }

    auto exe_sections = get_search_sections();
    if (!sse42old && !sse42new && !avx) {
        for (auto &section : exe_sections) {
            auto section_size = section.end() - section.begin();
            if (section_size > 1) {
                for (uintptr_t offset = section.begin(); offset < section.end(); ++offset) {
                    for (auto &pattern : patterns) {
                        if (does_match(pattern, offset)) {
                            auto n = offset - (uintptr_t)search_buffer->data();
                            n      = n;
                            matches[std::get<0>(pattern)].emplace_back(offset);
                        }
                    }
                }
            }
        }
    } else if(avx) {
        // SSE
        struct SSEPatternData {
            __m256i first;
            __m256i last;
            size_t  spread;
            size_t  data_size;
            std::tuple<std::string, std::string> pattern;
        };

        std::vector<SSEPatternData> sse_patterns;

        for (auto &pattern : patterns) {
            auto &[mask, bytes] = pattern;

            const auto mask_size = std::min(mask.size(), size_t(32));
            const auto data_size = std::min(bytes.size(), size_t(32));

            __m256i first  = _mm256_set1_epi8(0);
            __m256i last   = _mm256_set1_epi8(0);
            int32_t ifirst = 0;
            int32_t ilast  = 0;
            
            for (int32_t i = 0; i < mask_size; ++i) {
                 if (mask[i] != '?') {
                    first  = _mm256_set1_epi8(bytes[i]);
                     ifirst = i;
                     break;
                 }
            }
            for (int32_t i = mask_size - 1; i >= 0; --i) {
                if (mask[i] != '?') {
                    last  = _mm256_set1_epi8(bytes[i]);
                    ilast = i;
                    break;
                }
            }

            sse_patterns.emplace_back(SSEPatternData{first, last, static_cast<size_t>(ilast - ifirst), data_size, pattern});
        }

        for (auto &section : exe_sections) {
            const auto section_size = section.end() - section.begin();
            if (!(section_size > 32)) {
                continue;
            }
            auto end = section.end() - 32;

            for (uintptr_t offset = section.begin(); offset < end; offset += 32) {
                for (auto &s_pattern : sse_patterns) {
                    auto &&[first, last, spread, data_size, pattern] = s_pattern;

                    // I think this may be somewhat slow....
                    const __m256i block_first =
                        _mm256_loadu_si256(reinterpret_cast<const __m256i *>(offset));
                    const __m256i block_last =
                        _mm256_loadu_si256(reinterpret_cast<const __m256i *>(offset + spread));

                    const __m256i eq_first = _mm256_cmpeq_epi8(first, block_first);
                    const __m256i eq_last  = _mm256_cmpeq_epi8(last, block_last);

                    uint32_t mask = _mm256_movemask_epi8(_mm256_and_si256(eq_first, eq_last));
               
                    while (mask != 0) {

                        const auto bitpos = ctz(mask);

                        if (does_match(pattern, offset + bitpos)) {
                            matches[std::get<0>(pattern)].emplace_back(offset + bitpos);
                            break;
                        }

                        mask = mask & (mask - 1);
                    }
                }
            }
        }
    } else if(sse42new) {
        struct SSEPatternData {
            __m128i                              first;
            __m128i                              last;
            size_t                               spread;
            size_t                               data_size;
            std::tuple<std::string, std::string> pattern;
        };

        std::vector<SSEPatternData> sse_patterns;

        for (auto &pattern : patterns) {
            auto &[mask, bytes] = pattern;

            const auto mask_size = std::min(mask.size(), size_t(16));
            const auto data_size = std::min(bytes.size(), size_t(16));

            __m128i first  = _mm_set1_epi8(0);
            __m128i last   = _mm_set1_epi8(0);
            int32_t ifirst = 0;
            int32_t ilast  = 0;

            for (int32_t i = 0; i < mask_size; ++i) {
                if (mask[i] != '?') {
                    first  = _mm_set1_epi8(bytes[i]);
                    ifirst = i;
                    break;
                }
            }
            for (int32_t i = mask_size - 1; i >= 0; --i) {
                if (mask[i] != '?') {
                    last  = _mm_set1_epi8(bytes[i]);
                    ilast = i;
                    break;
                }
            }

            sse_patterns.emplace_back(SSEPatternData{
                first, last, static_cast<size_t>(ilast - ifirst), data_size, pattern});
        }

        for (auto &section : exe_sections) {
            const auto section_size = section.end() - section.begin();
            if (!(section_size > 16)) {
                continue;
            }
            auto end = section.end() - 16;

            for (uintptr_t offset = section.begin(); offset < end; offset += 16) {
                for (auto &s_pattern : sse_patterns) {
                    auto &&[first, last, spread, data_size, pattern] = s_pattern;
                    // Load 32 bytes from the start and from the end
                    // We try to match the first and last byte in each, if we find one
                    // We know that we have a potential match

                    // This is rather slow :( 
                    // 7 latency, throughput 0.5
                    // Maybe do 2 or more at a time?
                    const __m128i block_first =
                        _mm_loadu_si128(reinterpret_cast<const __m128i *>(offset));
                    const __m128i block_last =
                        _mm_loadu_si128(reinterpret_cast<const __m128i *>(offset + spread));

                    const __m128i eq_first = _mm_cmpeq_epi8(first, block_first);
                    const __m128i eq_last  = _mm_cmpeq_epi8(last, block_last);

                    uint32_t mask = _mm_movemask_epi8(_mm_and_si128(eq_first, eq_last));

                    while (mask != 0) {

                        const auto bitpos = ctz(mask);

                        if (does_match(pattern, offset + bitpos)) {
                            matches[std::get<0>(pattern)].emplace_back(offset + bitpos);
                            break;
                        }

                        mask = mask & (mask - 1);
                    }
                }
            }
        }
    } else if (sse42old) {
        struct SSEPatternData {
            __m128i                              smask;
            __m128i                              comparand;
            size_t                               data_size;
            std::tuple<std::string, std::string> pattern;
        };

        std::vector<SSEPatternData> sse_patterns;

        __declspec(align(16)) char desired_mask[16] = {0};
        for (auto &pattern : patterns) {
            auto &[mask, bytes] = pattern;

            const auto mask_size = std::min(mask.size(), size_t(16));
            const auto data_size = std::min(bytes.size(), size_t(16));

            for (int32_t i = 0; i < mask_size; i++) {
                desired_mask[i / 8] |= ((mask[i] == '?') ? 0 : 1) << (i % 8);
            }

            __m128i smask     = _mm_load_si128(reinterpret_cast<const __m128i *>(desired_mask));
            __m128i comparand = _mm_loadu_si128(reinterpret_cast<const __m128i *>(bytes.c_str()));

            sse_patterns.emplace_back(SSEPatternData{smask, comparand, data_size, pattern});
        }

        for (auto &section : exe_sections) {
            const auto section_size = section.end() - section.begin();
            if (!(section_size > 16)) {
                continue;
            }
            auto end = section.end() - 16;

            for (uintptr_t offset = section.begin(); offset < end; ++offset) {
                for (auto &s_pattern : sse_patterns) {
                    auto &&[mask, comparand, data_size, pattern] = s_pattern;

                    __m128i value = _mm_loadu_si128(reinterpret_cast<const __m128i *>(offset));

                    __m128i result = _mm_cmpestrm(value, 16, comparand, static_cast<int>(data_size),
                                                  _SIDD_CMP_EQUAL_EACH);

                    // as the result can match more bits than the mask contains
                    __m128i match       = _mm_and_si128(mask, result);
                    __m128i equivalence = _mm_xor_si128(mask, match);

                    if (_mm_test_all_zeros(equivalence, equivalence)) {
                        // Because we might only do partial match, make sure we actually
                        // have a full match
                        if (does_match(pattern, offset)) {
                            matches[std::get<0>(pattern)].emplace_back(offset);
                        }
                    }
                }
            }
        }
    }

    // Remove duplicates
    for (auto& match : matches) {
        auto end = match.second.end();
        for (auto it = match.second.begin(); it != end; ++it) {
            end = std::remove(it + 1, end, *it);
        }
        match.second.erase(end, match.second.end());
    }
   

    save_hints(matches);

    return matches;
}

} // namespace meow_hook
