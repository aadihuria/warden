cmake_minimum_required(VERSION 3.20)
project(warden LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

option(WARDEN_ENABLE_SANITIZERS "Build with ASan/UBSan enabled" OFF)
option(WARDEN_ENABLE_TSAN "Build with ThreadSanitizer enabled (mutually exclusive with ASan)" OFF)

find_package(CURL REQUIRED)

add_library(warden_core STATIC
    src/taint.cpp
    src/policy.cpp
    src/attribution.cpp
    src/quorum.cpp
    src/verifiers.cpp
    src/anthropic_verifier.cpp
    src/ledger.cpp
    src/replication.cpp
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
    tests/test_replication.cpp
    tests/main.cpp
)
target_link_libraries(warden_tests PRIVATE warden::core)

if(WARDEN_ENABLE_SANITIZERS)
    foreach(tgt warden_core warden-proxy warden_tests)
        target_compile_options(${tgt} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(${tgt} PRIVATE -fsanitize=address,undefined)
    endforeach()
endif()

if(WARDEN_ENABLE_TSAN)
    foreach(tgt warden_core warden-proxy warden_tests)
        target_compile_options(${tgt} PRIVATE -fsanitize=thread -fno-omit-frame-pointer)
        target_link_options(${tgt} PRIVATE -fsanitize=thread)
    endforeach()
endif()

enable_testing()
add_test(NAME warden_unit_tests COMMAND warden_tests)

# --- install rules, so `cmake --install build` gives a real, usable
# installed binary (/usr/local/bin/warden-proxy by default) instead of
# only a build-tree artifact. ---
include(GNUInstallDirs)
install(TARGETS warden-proxy
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(TARGETS warden_core
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
install(DIRECTORY include/warden
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
