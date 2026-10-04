if(NOT MSEC_WITH_OPENSSL OR NOT MSEC_WITH_PAHO)
    message(STATUS "load gateway skipped: requires MSEC_WITH_OPENSSL and MSEC_WITH_PAHO")
    return()
endif()

add_executable(msec_load_gateway main.cpp)
target_link_libraries(msec_load_gateway PRIVATE
    msec::mqtt msec::security msec::data msec::project_options)
