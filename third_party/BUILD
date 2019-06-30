cc_library(
    name = "spdlog",
    hdrs = glob(["spdlog/include/**/*.h"]),
    defines = [
        "SPDLOG_WCHAR_FILENAMES",
    ],
    includes = [
        "spdlog/include",
    ],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "zycore",
    srcs = glob(["zydis/dependencies/zycore/src/**/*.c"]),
    hdrs = glob(["zydis/dependencies/zycore/include/**/*.h"]),
    defines = [
        "ZYCORE_STATIC_DEFINE",
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
    srcs = glob([
        "zydis/src/**/*.c",
        "zydis/src/**/*.inc",
    ]),
    hdrs = glob(["zydis/include/**/*.h"]),
    copts = ["-Ithird_party/zydis/src"],  # GOD THIS SUCKS SOOOOO MUCH, WHY BAZEL WHY, I LIKE YOU BUT INCLUDE PATHS ARE JUST GARBAGE
    defines = [
        "ZYDIS_STATIC_DEFINE",
    ],
    includes = [
        "zydis/include",
        "zydis/src",  # OH WELL BAZEL
    ] + select({
        "@bazel_tools//src/conditions:windows": ["zydis/msvc"],
        "//conditions:default": [],
    }),
    visibility = ["//visibility:public"],
    deps = [
        ":zycore",
    ],
)

cc_library(
    name = "asmjit",
    srcs = glob(["asmjit/src/**/*.cpp"]),
    hdrs = glob(["asmjit/src/**/*.h"]),
    defines = [
        "ASMJIT_STATIC",
    ],
    includes = [
        "asmjit/src",
    ],
    visibility = ["//visibility:public"],
)
