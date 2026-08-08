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

add_subdirectory(schemes)

add_executable(benchmark benchmark.cpp)
target_link_libraries(benchmark PRIVATE schemes)
