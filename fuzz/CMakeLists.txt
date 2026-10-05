# libFuzzer targets for the code that parses attacker-controlled bytes.
# Build with the `fuzz` preset (Clang), then e.g.:
#   ./build/fuzz/fuzz/fuzz_envelope fuzz/corpus/envelope -max_total_time=60
if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "MSEC_BUILD_FUZZERS needs Clang (libFuzzer): use the `fuzz` preset")
endif()

function(msec_add_fuzzer name)
    add_executable(${name} ${name}.cpp)
    target_link_libraries(${name} PRIVATE ${ARGN} msec::project_options)
    target_compile_options(${name} PRIVATE -fsanitize=fuzzer)
    target_link_options(${name} PRIVATE -fsanitize=fuzzer)
endfunction()

msec_add_fuzzer(fuzz_topic msec::core)
msec_add_fuzzer(fuzz_envelope msec::security)
msec_add_fuzzer(fuzz_security_inbound msec::security)
