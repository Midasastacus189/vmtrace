cmake_minimum_required(VERSION 3.20)

project(whp_cpuid_spoof LANGUAGES CXX)

add_executable(whp_cpuid_spoof
    src/main.cpp
)

target_compile_features(whp_cpuid_spoof PRIVATE cxx_std_20)

target_compile_definitions(whp_cpuid_spoof PRIVATE
    NOMINMAX
    WIN32_LEAN_AND_MEAN
)

target_link_libraries(whp_cpuid_spoof PRIVATE
    WinHvPlatform
)
