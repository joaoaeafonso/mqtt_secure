if(MSEC_ENABLE_CLANG_TIDY)
    find_program(MSEC_CLANG_TIDY_EXE NAMES clang-tidy REQUIRED)
    # Applied per-target in msec_add_module() so third-party code is not analysed.
    # clang-tidy parses the GCC command line with Clang:
    #  - GCC-only warning flags (-Wduplicated-cond, …) are not errors for it;
    #  - libstdc++ 13 exposes std::expected only when __cpp_concepts >= 202002L,
    #    which Clang 18 implements but does not advertise.
    set(MSEC_CLANG_TIDY_COMMAND
        "${MSEC_CLANG_TIDY_EXE};--warnings-as-errors=*"
        "--extra-arg=-Wno-unknown-warning-option"
        "--extra-arg=-D__cpp_concepts=202002L"
        "--extra-arg=-Wno-builtin-macro-redefined")
endif()
