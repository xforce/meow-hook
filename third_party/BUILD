cc_library(
    name = "spdlog",
    defines = [
        "SPDLOG_WCHAR_FILENAMES"
    ],
    hdrs = glob(["spdlog/include/**/*.h"]),
    includes = [
        "spdlog/include",
    ],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "zycore",
    hdrs = glob(["zydis/dependencies/zycore/include/**/*.h"]),
    srcs = glob(["zydis/dependencies/zycore/src/**/*.c"]),
    defines = [
        "ZYCORE_STATIC_DEFINE"
    ],
    includes = [
        "zydis/dependencies/zycore/include",
    ] + select({
        "@bazel_tools//src/conditions:windows": ["zydis/msvc"],
        "//conditions:default": [],
    }),
    visibility = ["//visibility:public"],
)

cc_library(
    name = "zydis",
    hdrs = glob(["zydis/include/**/*.h"]),
    srcs = glob(["zydis/src/**/*.c", "zydis/src/**/*.inc"]),
    defines = [
        "ZYDIS_STATIC_DEFINE"
    ],
    includes = [
        "zydis/include",
    ] + select({
        "@bazel_tools//src/conditions:windows": ["zydis/msvc"],
        "//conditions:default": [],
    }),
    copts = ["-Ithird_party/zydis/src"], # GOD THIS SUCKS SOOOOO MUCH, WHY BAZEL WHY, I LIKE YOU BUT INCLUDE PATHS ARE JUST GARBAGE
    visibility = ["//visibility:public"],
    deps = [
        ":zycore"
    ]
)

cc_library(
    name = "asmjit",
    defines = [ ],
    hdrs = glob(["asmjit/src/**/*.h"]),
    srcs = glob(["asmjit/src/**/*.cpp"]),
    includes = [
        "asmjit/src",
    ],
    visibility = ["//visibility:public"],
)
