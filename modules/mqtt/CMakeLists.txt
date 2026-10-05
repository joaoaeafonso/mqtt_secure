set(_sources
    src/access_control.cpp
    src/loopback_broker.cpp
    src/endpoint.cpp)

if(MSEC_WITH_PAHO)
    list(APPEND _sources src/paho/paho_client.cpp)
endif()

msec_add_module(
    NAME         mqtt
    SOURCES      ${_sources}
    PUBLIC_DEPS  msec::core
    PRIVATE_DEPS $<$<BOOL:${MSEC_WITH_PAHO}>:PahoMqttCpp::paho-mqttpp3>)
