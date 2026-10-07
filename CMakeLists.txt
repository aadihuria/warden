cmake_minimum_required(VERSION 3.20)
project(warden LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

option(WARDEN_ENABLE_SANITIZERS "Build with ASan/UBSan enabled" OFF)

find_package(CURL REQUIRED)

add_library(warden_core STATIC
    src/taint.cpp
    src/policy.cpp
    src/attribution.cpp
    src/quorum.cpp
    src/verifiers.cpp
    src/anthropic_verifier.cpp
    src/ledger.cpp
    third_party/sha256.c
)
target_include_directories(warden_core PUBLIC include third_party)
target_link_libraries(warden_core PUBLIC CURL::libcurl)

add_library(warden::core ALIAS warden_core)

add_executable(warden-proxy src/proxy_main.cpp)
target_include_directories(warden-proxy PRIVATE third_party)
target_link_libraries(warden-proxy PRIVATE warden::core)
find_package(Threads REQUIRED)
target_link_libraries(warden-proxy PRIVATE Threads::Threads)

add_executable(warden_tests
    tests/test_taint.cpp
    tests/test_policy.cpp
    tests/test_attribution.cpp
    tests/test_quorum.cpp
    tests/test_ledger.cpp
    tests/main.cpp
)
target_link_libraries(warden_tests PRIVATE warden::core)

if(WARDEN_ENABLE_SANITIZERS)
    foreach(tgt warden_core warden-proxy warden_tests)
        target_compile_options(${tgt} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(${tgt} PRIVATE -fsanitize=address,undefined)
    endforeach()
endif()

enable_testing()
add_test(NAME warden_unit_tests COMMAND warden_tests)
