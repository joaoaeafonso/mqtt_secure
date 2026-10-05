cmake_minimum_required(VERSION 3.25)

project(mqtt_secure
    VERSION 0.1.0
    DESCRIPTION "Layered security architecture for MQTT-based IoT communication"
    LANGUAGES CXX)

# ---------------------------------------------------------------------------
# Global language settings. C++23 is the floor; never fall back silently.
# ---------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
    message(FATAL_ERROR "In-source builds are not allowed. Use: cmake --preset dev")
endif()

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
option(MSEC_WARNINGS_AS_ERRORS "Treat compiler warnings as errors"      ON)
option(MSEC_ENABLE_SANITIZERS  "Build with ASan + UBSan"                OFF)
option(MSEC_ENABLE_TSAN        "Build with ThreadSanitizer"             OFF)
option(MSEC_ENABLE_CLANG_TIDY  "Run clang-tidy during compilation"      OFF)
option(MSEC_ENABLE_HARDENING   "Enable compiler/linker hardening flags" ON)
option(MSEC_BUILD_TESTS        "Build unit tests"                       ON)
option(MSEC_BUILD_APPS         "Build example applications"             ON)
option(MSEC_BUILD_BENCHMARKS   "Build performance benchmarks"           OFF)
option(MSEC_BUILD_FUZZERS      "Build libFuzzer targets (Clang)"        OFF)
option(MSEC_WITH_OPENSSL       "Build the OpenSSL crypto backend"       ON)
option(MSEC_WITH_PAHO          "Build the Eclipse Paho MQTT client"     ON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(ProjectOptions)   # msec::project_options (warnings, sanitizers, hardening)
if(MSEC_BUILD_FUZZERS)
    # Coverage instrumentation for every first-party library the fuzzers link.
    target_compile_options(msec_project_options INTERFACE -fsanitize=fuzzer-no-link)
endif()
include(StaticAnalysis)
include(MsecModule)       # msec_add_module(), msec_add_test()

if(MSEC_WITH_OPENSSL)
    find_package(OpenSSL 3.0 REQUIRED)
endif()
if(MSEC_WITH_PAHO)
    find_package(PahoMqttCpp REQUIRED)  # set MSEC_WITH_PAHO=OFF to build without it
endif()

# ---------------------------------------------------------------------------
# Modules. Order matters only for readability; dependencies are explicit.
# To add a layer: create modules/<name>/ and add_subdirectory() it here.
# ---------------------------------------------------------------------------
add_subdirectory(modules/core)
add_subdirectory(modules/mqtt)
add_subdirectory(modules/security)
add_subdirectory(modules/data)
add_subdirectory(modules/limits)

if(MSEC_BUILD_APPS)
    add_subdirectory(apps/gateway)
    add_subdirectory(apps/load_gateway)
endif()

if(MSEC_BUILD_BENCHMARKS)
    if(NOT MSEC_WITH_OPENSSL)
        message(FATAL_ERROR "MSEC_BUILD_BENCHMARKS requires MSEC_WITH_OPENSSL")
    endif()
    add_subdirectory(benchmarks)
endif()

if(MSEC_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(MSEC_BUILD_FUZZERS)
    add_subdirectory(fuzz)
endif()
