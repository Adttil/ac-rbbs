cmake_minimum_required(VERSION 3.28)

project(anonymous_credential_experiment LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(FetchContent)

set(CRYPTO12381_INCLUDE_EXAMPLES OFF CACHE BOOL "Build crypto12381 examples" FORCE)
FetchContent_Declare(
    crypto12381
    GIT_REPOSITORY https://github.com/Adttil/crypto12381.git
    GIT_TAG main
    EXCLUDE_FROM_ALL
)
FetchContent_MakeAvailable(crypto12381)

FetchContent_Declare(
    cxxopts
    GIT_REPOSITORY https://github.com/jarro2783/cxxopts.git
    GIT_TAG v3.3.1
    EXCLUDE_FROM_ALL
)
FetchContent_MakeAvailable(cxxopts)

set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "Build Google Benchmark tests" FORCE)
set(BENCHMARK_ENABLE_GTEST_TESTS OFF CACHE BOOL "Build Google Benchmark GoogleTest tests" FORCE)
set(BENCHMARK_ENABLE_INSTALL OFF CACHE BOOL "Install Google Benchmark" FORCE)
set(BENCHMARK_ENABLE_WERROR OFF CACHE BOOL "Treat Google Benchmark warnings as errors" FORCE)
FetchContent_Declare(
    google_benchmark
    GIT_REPOSITORY https://github.com/google/benchmark.git
    GIT_TAG v1.9.5
    EXCLUDE_FROM_ALL
)
FetchContent_MakeAvailable(google_benchmark)

add_subdirectory(schemes)

add_executable(benchmark_runner benchmark.cpp)
set_target_properties(benchmark_runner PROPERTIES OUTPUT_NAME benchmark)
target_link_libraries(benchmark_runner PRIVATE schemes cxxopts::cxxopts benchmark::benchmark)
