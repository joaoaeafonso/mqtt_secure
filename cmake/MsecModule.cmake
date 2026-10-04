# msec_add_module(
#     NAME          <name>            # creates target msec_<name> + alias msec::<name>
#     SOURCES       <files...>
#     PUBLIC_DEPS   <targets...>      # exposed through this module's headers
#     PRIVATE_DEPS  <targets...>)     # implementation detail only
#
# Every module follows the same layout:
#   modules/<name>/include/msec/<name>/*.hpp   public API
#   modules/<name>/src/*.cpp                   implementation
function(msec_add_module)
    cmake_parse_arguments(ARG "" "NAME" "SOURCES;PUBLIC_DEPS;PRIVATE_DEPS" ${ARGN})
    if(NOT ARG_NAME)
        message(FATAL_ERROR "msec_add_module: NAME is required")
    endif()

    set(_target msec_${ARG_NAME})
    add_library(${_target} ${ARG_SOURCES})
    add_library(msec::${ARG_NAME} ALIAS ${_target})

    target_include_directories(${_target} PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>)
    target_compile_features(${_target} PUBLIC cxx_std_23)
    target_link_libraries(${_target}
        PUBLIC  ${ARG_PUBLIC_DEPS}
        PRIVATE ${ARG_PRIVATE_DEPS} msec::project_options)

    set_target_properties(${_target} PROPERTIES
        POSITION_INDEPENDENT_CODE ON
        OUTPUT_NAME msec_${ARG_NAME})

    if(MSEC_CLANG_TIDY_COMMAND)
        set_target_properties(${_target} PROPERTIES CXX_CLANG_TIDY "${MSEC_CLANG_TIDY_COMMAND}")
    endif()
endfunction()

# msec_add_test(NAME <name> SOURCES <files...> DEPS <targets...>)
function(msec_add_test)
    cmake_parse_arguments(ARG "" "NAME" "SOURCES;DEPS" ${ARGN})
    add_executable(${ARG_NAME} ${ARG_SOURCES})
    target_link_libraries(${ARG_NAME} PRIVATE
        ${ARG_DEPS} GTest::gtest_main msec::project_options)
    gtest_discover_tests(${ARG_NAME} DISCOVERY_TIMEOUT 30)
endfunction()
