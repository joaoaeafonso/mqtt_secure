find_package(GTest 1.14 QUIET)
if(NOT GTest_FOUND)
    include(FetchContent)
    FetchContent_Declare(googletest
        URL      https://github.com/google/googletest/archive/refs/tags/v1.15.2.tar.gz
        URL_HASH SHA256=7b42b4d6ed48810c5362c265a17faebe90dc2373c885e5216439d37927f02926
        SYSTEM)
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
    set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
endif()
include(GoogleTest)

msec_add_test(NAME core_tests  SOURCES core_tests.cpp  DEPS msec::core)
msec_add_test(NAME mqtt_tests  SOURCES mqtt_tests.cpp  DEPS msec::mqtt)
msec_add_test(NAME data_tests  SOURCES data_tests.cpp  DEPS msec::data)
msec_add_test(NAME limits_tests SOURCES limits_tests.cpp DEPS msec::limits)

if(MSEC_WITH_OPENSSL)
    msec_add_test(NAME security_tests    SOURCES security_tests.cpp    DEPS msec::security)
    target_compile_definitions(security_tests PRIVATE
        MSEC_ENVELOPE_VECTORS="${CMAKE_CURRENT_SOURCE_DIR}/vectors/envelope_vectors.txt")
    msec_add_test(NAME acceptance_tests  SOURCES acceptance_tests.cpp  DEPS msec::security)
    msec_add_test(NAME integration_tests SOURCES integration_tests.cpp
                  DEPS msec::mqtt msec::security msec::data)
endif()
