if(MSEC_ENABLE_CLANG_TIDY)
    find_program(MSEC_CLANG_TIDY_EXE NAMES clang-tidy REQUIRED)
    # Applied per-target in msec_add_module() so third-party code is not analysed.
    set(MSEC_CLANG_TIDY_COMMAND "${MSEC_CLANG_TIDY_EXE};--warnings-as-errors=*")
endif()
