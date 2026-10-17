# libmsec_sslkeylog.so: LD_PRELOAD shim that makes mosquitto and
# msec_load_gateway log TLS secrets for Wireshark (see sslkeylog.cpp).
# Loaded into foreign processes, so it is built without sanitizers and does
# not link msec::project_options' sanitizer flags.
if(NOT MSEC_WITH_OPENSSL OR NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    return()
endif()

add_library(msec_sslkeylog MODULE sslkeylog.cpp)
set_target_properties(msec_sslkeylog PROPERTIES PREFIX "lib" OUTPUT_NAME msec_sslkeylog)
target_compile_features(msec_sslkeylog PRIVATE cxx_std_23)
if(NOT MSVC)
    target_compile_options(msec_sslkeylog PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()
target_link_libraries(msec_sslkeylog PRIVATE OpenSSL::SSL ${CMAKE_DL_LIBS})
