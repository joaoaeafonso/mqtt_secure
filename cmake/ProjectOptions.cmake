# Defines msec::project_options, an INTERFACE target carrying every
# project-wide compile/link policy. Each first-party target links it PRIVATELY
# so these flags never leak into third-party code (GoogleTest, OpenSSL, ...).

add_library(msec_project_options INTERFACE)
add_library(msec::project_options ALIAS msec_project_options)

# ----- Warnings -------------------------------------------------------------
set(_msec_common_warnings
    -Wall -Wextra -Wpedantic
    -Wshadow -Wconversion -Wsign-conversion
    -Wold-style-cast -Wcast-align -Wnon-virtual-dtor -Woverloaded-virtual
    -Wnull-dereference -Wdouble-promotion -Wformat=2 -Wimplicit-fallthrough
    -Wunused -Wmissing-declarations)

set(_msec_gcc_warnings
    -Wduplicated-cond -Wduplicated-branches -Wlogical-op -Wuseless-cast)

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(msec_project_options INTERFACE
        ${_msec_common_warnings} ${_msec_gcc_warnings})
elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    target_compile_options(msec_project_options INTERFACE ${_msec_common_warnings})
elseif(MSVC)
    target_compile_options(msec_project_options INTERFACE /W4 /permissive- /utf-8)
endif()

if(MSEC_WARNINGS_AS_ERRORS)
    if(MSVC)
        target_compile_options(msec_project_options INTERFACE /WX)
    else()
        target_compile_options(msec_project_options INTERFACE -Werror)
    endif()
endif()

# ----- Hardening ------------------------------------------------------------
if(MSEC_ENABLE_HARDENING AND NOT MSVC)
    target_compile_options(msec_project_options INTERFACE
        -fstack-protector-strong
        -fno-omit-frame-pointer
        $<$<NOT:$<CONFIG:Debug>>:-D_FORTIFY_SOURCE=3>
        -D_GLIBCXX_ASSERTIONS)       # bounds-checked std containers
    if(NOT APPLE)
        target_link_options(msec_project_options INTERFACE
            -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack)
    endif()
endif()

# ----- Sanitizers -----------------------------------------------------------
if(MSEC_ENABLE_SANITIZERS AND MSEC_ENABLE_TSAN)
    message(FATAL_ERROR "ASan/UBSan and TSan cannot be combined")
endif()

if(MSEC_ENABLE_SANITIZERS AND NOT MSVC)
    set(_san -fsanitize=address,undefined -fno-sanitize-recover=all)
    target_compile_options(msec_project_options INTERFACE ${_san})
    target_link_options(msec_project_options INTERFACE ${_san})
endif()

if(MSEC_ENABLE_TSAN AND NOT MSVC)
    target_compile_options(msec_project_options INTERFACE -fsanitize=thread)
    target_link_options(msec_project_options INTERFACE -fsanitize=thread)
endif()
