
target_sources(Fulcrum PRIVATE
    amount.cpp
    base58.cpp
    block.cpp
    cashaddr.cpp
    cashaddrenc.cpp
    hash.cpp
    interpreter.cpp
    pubkey.cpp
    script.cpp
    script_error.cpp
    script_standard.cpp
    sigencoding.cpp
    test.cpp
    token.cpp
    transaction.cpp
    uint256.cpp
    utilstrencodings.cpp
    utilstring.cpp
    # Crypto
    crypto/aes.cpp
    crypto/chacha20.cpp
    crypto/hmac_sha256.cpp
    crypto/hmac_sha512.cpp
    crypto/ripemd160.cpp
    crypto/sha1.cpp
    crypto/sha256.cpp
    crypto/sha256_sse4.cpp
    crypto/sha512.cpp
    # ctaes
    crypto/ctaes/ctaes.c
    # secp
    secp256k1/secp256k1.c
)
