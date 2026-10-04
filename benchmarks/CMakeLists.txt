find_package(benchmark 1.8 QUIET)
if(NOT benchmark_FOUND)
    include(FetchContent)
    FetchContent_Declare(googlebenchmark
        URL      https://github.com/google/benchmark/archive/refs/tags/v1.9.1.tar.gz
        URL_HASH SHA256=32131c08ee31eeff2c8968d7e874f3cb648034377dfc32a4c377fa8796d84981
        SYSTEM)
    set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "" FORCE)
    set(BENCHMARK_ENABLE_GTEST_TESTS OFF CACHE BOOL "" FORCE)
    set(BENCHMARK_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)
    set(BENCHMARK_ENABLE_WERROR OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googlebenchmark)
endif()

add_executable(msec_pipeline_benchmarks pipeline_benchmarks.cpp)
target_link_libraries(msec_pipeline_benchmarks PRIVATE
    msec::mqtt msec::security msec::data benchmark::benchmark msec::project_options)
