# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.11)

project("File Encryptor Sample" LANGUAGES C CXX)

find_package(OpenEnclave CONFIG REQUIRED)

set(CMAKE_CXX_STANDARD 11)
# set OE_CRYPTO_LIB to either "mbedtls" or "openssl" based on the crypto wrapper to be used.
# OE_CRYPTO_LIB is case sensitive. Use all lowercase letters.
set(OE_CRYPTO_LIB mbedtls)

add_subdirectory(enclave)
add_subdirectory(host)

# Generate key
add_custom_command(
  OUTPUT private.pem public.pem
  COMMAND openssl genrsa -out private.pem -3 3072
  COMMAND openssl rsa -in private.pem -pubout -out public.pem)

# Sign enclave
add_custom_command(
  OUTPUT enclave/enclave.signed
  DEPENDS enclave enclave/file-encryptor.conf private.pem
  COMMAND openenclave::oesign sign -e $<TARGET_FILE:enclave> -c
          ${CMAKE_SOURCE_DIR}/enclave/file-encryptor.conf -k private.pem)

add_custom_target(sign ALL DEPENDS enclave/enclave.signed)

if ((NOT DEFINED ENV{OE_SIMULATION}) OR (NOT $ENV{OE_SIMULATION}))
  add_custom_target(
    run
    DEPENDS file-encryptor_host sign testfile
    COMMAND file-encryptor_host ${CMAKE_CURRENT_SOURCE_DIR}/testfile
            ${CMAKE_BINARY_DIR}/enclave/enclave.signed)
endif ()

add_custom_target(
  simulate
  DEPENDS file-encryptor_host sign testfile
  COMMAND file-encryptor_host ${CMAKE_CURRENT_SOURCE_DIR}/testfile
          ${CMAKE_BINARY_DIR}/enclave/enclave.signed --simulate)
