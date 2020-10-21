# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(OPENSSL_DIR ${PROJECT_SOURCE_DIR}/3rdparty/openssl/openssl)
set(EDL_FILE ../openssl_moretest.edl)

add_custom_command(
  OUTPUT openssl_moretest_u.h openssl_moretest_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(
  openssl_moretest_host
  host.cpp
  Asymmetric_Encryptiont_tests.cpp
  akamai_tests.cpp
  cipher_tests.cpp
  digest_tests.cpp
  keygen_test.cpp
  CSchema_checker.cpp
  openssl_moretest_u.c)

target_compile_options(openssl_moretest_host PRIVATE -Wno-unused-parameter)

target_include_directories(
  openssl_moretest_host
  PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
          ${OPENSSL_DIR}
          ${OPENSSL_DIR}/include
          ${CMAKE_BINARY_DIR}/3rdparty/openssl/build/include
          ${OPENSSL_DIR}/crypto/x509
          ${OPENSSL_DIR}/crypto/rsa
          ${OPENSSL_DIR}/crypto/bn
          ${OPENSSL_DIR}/crypto/evp
          ${OPENSSL_DIR}/crypto/hmac
          ${CMAKE_CURRENT_SOURCE_DIR}
          ${CMAKE_CURRENT_SOURCE_DIR}/../include
          ${CMAKE_CURRENT_SOURCE_DIR}/../common_code)
target_link_libraries(openssl_moretest_host oehost)
