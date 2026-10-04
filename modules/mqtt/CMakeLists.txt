msec_add_module(
    NAME        mqtt
    SOURCES     src/topic_filter.cpp
                src/loopback_broker.cpp
                src/endpoint.cpp
    PUBLIC_DEPS msec::core)
