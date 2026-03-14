cmake_minimum_required(VERSION 3.20)

project(whp_lazy_emulator LANGUAGES CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_library(whp_lazy_emulator_lib STATIC
    src/whp_lazy_emulator.cpp
)

target_compile_features(whp_lazy_emulator_lib PRIVATE cxx_std_20)

target_compile_definitions(whp_lazy_emulator_lib PRIVATE
    NOMINMAX
    WIN32_LEAN_AND_MEAN
)

target_include_directories(whp_lazy_emulator_lib PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(whp_lazy_emulator_lib PUBLIC
    WinHvPlatform
)

add_executable(whp_lazy_emulator
    src/main.cpp
)

target_compile_features(whp_lazy_emulator PRIVATE cxx_std_20)

target_compile_definitions(whp_lazy_emulator PRIVATE
    NOMINMAX
    WIN32_LEAN_AND_MEAN
)

target_link_libraries(whp_lazy_emulator PRIVATE
    whp_lazy_emulator_lib
)
