cmake_minimum_required(VERSION 3.26)
project(AES C)

set(CMAKE_C_STANDARD 11)

# Find OpenSSL package
find_package(OpenSSL REQUIRED)

# Include OpenSSL headers
include_directories(${OPENSSL_INCLUDE_DIR})

# Create the executable and link with OpenSSL library
add_executable(AES AES.c)
target_link_libraries(AES PRIVATE OpenSSL::SSL OpenSSL::Crypto)
