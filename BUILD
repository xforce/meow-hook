cc_library(
    name = "meow-hook",
    srcs = glob(["src/**/*.cc"]) + glob(["src/**/*.h"]),
    hdrs = glob(["include/**/*.h"]),
    includes = [
        "include",
    ],
    deps = [
        "//third_party:asmjit",
        "//third_party:zydis",
    ],
)
