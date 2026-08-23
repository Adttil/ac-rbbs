cmake_minimum_required(VERSION 3.28)

project(anonymous_credential_experiment LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(FetchContent)

FetchContent_Declare(
    crypto12381
    GIT_REPOSITORY https://github.com/Adttil/crypto12381.git
    GIT_TAG v0.2.1
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
