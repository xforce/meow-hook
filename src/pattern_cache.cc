#include "pattern_cache.h"

namespace meow_hook
{
pattern_cache& pattern_cache::instance()
{
    static pattern_cache cache;
    return cache;
}
} // namespace meow_hook
