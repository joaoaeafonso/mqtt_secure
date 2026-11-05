set(_sources
    src/key_store.cpp
    src/epoch_store.cpp
    src/key_policy.cpp
    src/envelope.cpp
    src/replay_guard.cpp
    src/security_layer.cpp)

if(MSEC_WITH_OPENSSL)
    list(APPEND _sources
        src/openssl/evp_aead.cpp
        src/openssl/aes_gcm_cipher.cpp
        src/openssl/chacha20_poly1305_cipher.cpp
        src/openssl/ed25519_signer.cpp
        src/openssl/random_source.cpp)
endif()

msec_add_module(
    NAME         security
    SOURCES      ${_sources}
    PUBLIC_DEPS  msec::core
    PRIVATE_DEPS $<$<BOOL:${MSEC_WITH_OPENSSL}>:OpenSSL::Crypto>)
