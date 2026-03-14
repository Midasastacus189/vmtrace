cmake_minimum_required(VERSION 3.20)

project(vmtrace VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

set(ASMJIT_EMBED ON CACHE BOOL "" FORCE)
set(ASMJIT_STATIC ON CACHE BOOL "" FORCE)
set(ASMJIT_NO_INSTALL ON CACHE BOOL "" FORCE)
add_subdirectory(third_party/asmjit)

add_library(vmtrace STATIC
    src/lib/vmtrace.cpp
)

add_library(vmtrace::vmtrace ALIAS vmtrace)

target_compile_features(vmtrace PUBLIC cxx_std_20)

target_compile_definitions(vmtrace PRIVATE
    NOMINMAX
    WIN32_LEAN_AND_MEAN
)

target_include_directories(vmtrace
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

target_link_libraries(vmtrace PUBLIC
    WinHvPlatform
)

add_executable(vmtrace_demo
    src/examples/demo_main.cpp
)

target_compile_features(vmtrace_demo PRIVATE cxx_std_20)

target_compile_definitions(vmtrace_demo PRIVATE
    NOMINMAX
    WIN32_LEAN_AND_MEAN
)

target_link_libraries(vmtrace_demo PRIVATE
    vmtrace
    asmjit::asmjit
)

set(vmtrace_install_cmakedir "${CMAKE_INSTALL_LIBDIR}/cmake/vmtrace")

install(
    TARGETS vmtrace vmtrace_demo
    EXPORT vmtrace_targets
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(
    DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/vmtrace/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/vmtrace
)

install(
    EXPORT vmtrace_targets
    NAMESPACE vmtrace::
    FILE vmtraceTargets.cmake
    DESTINATION ${vmtrace_install_cmakedir}
)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/vmtraceConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/vmtraceConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/vmtraceConfig.cmake"
    INSTALL_DESTINATION ${vmtrace_install_cmakedir}
)

install(
    FILES
        "${CMAKE_CURRENT_BINARY_DIR}/vmtraceConfig.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/vmtraceConfigVersion.cmake"
    DESTINATION ${vmtrace_install_cmakedir}
)
