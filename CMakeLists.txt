cmake_minimum_required (VERSION 3.11)
project (meow-hook)

set (ASMJIT_STATIC TRUE)
add_subdirectory(third_party/asmjit)
add_subdirectory(third_party/zydis)
add_subdirectory(third_party/spdlog)

add_library("meow-hook" STATIC)
target_compile_definitions("meow-hook" PRIVATE "NOMINMAX")
set_property(TARGET meow-hook PROPERTY CXX_STANDARD 17)

target_include_directories("meow-hook"
    PUBLIC "include"
    PRIVATE "src")

target_sources("meow-hook"
    PRIVATE
        "include/meow_hook/detour.h"
        "include/meow_hook/memory.h"
        "include/meow_hook/pattern_search.h"
        "include/meow_hook/util.h"

        "src/detour.cc"
        "src/detour_x86.cc"
        "src/detour_x86_64.cc"
        "src/memory.cc"
        "src/pattern_cache.cc"
        "src/pattern_cache.h"
        "src/pattern_search.cc"
)

target_link_libraries("meow-hook" "Zydis")
add_dependencies(meow-hook Zydis)

target_link_libraries("meow-hook" "asmjit")
add_dependencies(meow-hook asmjit)