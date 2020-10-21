# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../openssl_moretest.edl)

add_custom_command(
  OUTPUT openssl_moretest_t.h openssl_moretest_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  openssl_moretest_enc
  CXX
  UUID
  90c020e8-e5dd-11ea-adc1-0242ac120002
  SOURCES
  enc.cpp
  tests_ecalls.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../common_code/common_akamai.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../common_code/common_asym_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../common_code/common_cipher_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../common_code/common_digest_tests.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../common_code/common_keygen_tests.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/openssl_moretest_t.c)

enclave_compile_options(
  openssl_moretest_enc PRIVATE -Wno-shorten-64-to-32 -Wno-sign-conversion
  -Wno-conversion -Wno-unused-parameter)

enclave_include_directories(
  openssl_moretest_enc
  PRIVATE
  ${OPENSSL_DIR}
  ${OPENSSL_DIR}/include
  ${CMAKE_BINARY_DIR}/3rdparty/openssl/build/include
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/..
  ${CMAKE_CURRENT_SOURCE_DIR}/../common_code
  ${CMAKE_CURRENT_SOURCE_DIR}/../include)
enclave_link_libraries(openssl_moretest_enc oelibc openssl)
