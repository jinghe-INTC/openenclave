# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(OPENSSL_DIR ${PROJECT_SOURCE_DIR}/3rdparty/openssl/openssl)
add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

add_enclave_test(tests/openssl_moretest_digest openssl_moretest_host
                 openssl_moretest_enc 0)
add_enclave_test(tests/openssl_moretest_keygen openssl_moretest_host
                 openssl_moretest_enc 1)
add_enclave_test(tests/openssl_moretest_akamai openssl_moretest_host
                 openssl_moretest_enc 2)
add_enclave_test(tests/openssl_moretest_asym openssl_moretest_host
                 openssl_moretest_enc 3)
add_enclave_test(tests/openssl_moretest_cipher openssl_moretest_host
                 openssl_moretest_enc 4)
