cc_library(
    name = "meow-hook",
    srcs = glob(["src/**/*.cc"]) + glob(["src/**/*.h"]) + glob(["src/**/*.asm"]),
    hdrs = glob(["include/**/*.h"]),
    includes = [
        "include",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//third_party:asmjit",
        "//third_party:zydis",
    ],
)
