msec_add_module(
    NAME        data
    SOURCES     src/in_memory_repository.cpp
                src/persistence_layer.cpp
    PUBLIC_DEPS msec::core)
