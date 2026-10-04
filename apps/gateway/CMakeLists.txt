if(NOT MSEC_WITH_OPENSSL)
    message(STATUS "gateway demo skipped: requires MSEC_WITH_OPENSSL")
    return()
endif()

add_executable(msec_gateway_demo main.cpp)
target_link_libraries(msec_gateway_demo PRIVATE
    msec::mqtt msec::security msec::data msec::project_options)
