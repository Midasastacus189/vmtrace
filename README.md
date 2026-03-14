# vmtrace

[![Build](https://img.shields.io/github/actions/workflow/status/momo5502/vmtrace/build.yml?branch=main&label=build)](https://github.com/momo5502/vmtrace/actions/workflows/build.yml)
[![Platform](https://img.shields.io/badge/platform-Windows-0078D6)](https://github.com/momo5502/vmtrace)
[![C%2B%2B](https://img.shields.io/badge/C%2B%2B-20-00599C)](https://github.com/momo5502/vmtrace)
[![CMake](https://img.shields.io/badge/cmake-3.20%2B-064F8C)](https://github.com/momo5502/vmtrace)

`vmtrace` is a small Windows Hypervisor Platform library for trap-driven guest execution. It lets you start from a supplied CPU state, map guest memory from host pages, and react to memory, `CPUID`, and syscall-related exits in user mode.

## Features

- Static C++ library with a small public API
- Host-backed guest memory mappings
- Page-level trap handling for read, write, and execute faults
- `CPUID` interception
- Syscall interception for controlled guest experiments
- Example program that assembles guest code with `asmjit`

## Repository Layout

- [`include/vmtrace/vmtrace.hpp`](include/vmtrace/vmtrace.hpp): public library API
- [`src/lib/vmtrace.cpp`](src/lib/vmtrace.cpp): WHP-backed implementation
- [`src/examples/demo_main.cpp`](src/examples/demo_main.cpp): demo that runs `cpuid` and a syscall in the guest

## Prerequisites

To run the demo locally, enable these Windows features and reboot:

- `Microsoft-Hyper-V-Hypervisor`
- `HypervisorPlatform`

Building the project does not require running Hyper-V guests, but executing the demo does.

## Build

Use a shell with MSVC available, for example `x64 Native Tools Command Prompt for VS`:

```powershell
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

## Run

```powershell
.\build\vmtrace_demo.exe
```

Expected output looks like:

```text
Starting vmtrace demo
Intercepted CPUID leaf=0x0 subleaf=0x0
Intercepted syscall number=0x1234 arg0=0x11111111 arg1=0x22222222 arg2=0x33333333 arg3=0x44444444
Final registers
  RIP: 0x...
  RAX: 0xfeedfacecafebeef
Vendor captured in guest memory: VmTraceLabs!
Syscall return captured in guest memory: 0xfeedfacecafebeef
```

## Install

The project exports a CMake package:

```powershell
cmake --install build --prefix .\build\install
```

Then consume it with:

```cmake
find_package(vmtrace CONFIG REQUIRED)
target_link_libraries(your_target PRIVATE vmtrace::vmtrace)
```

## CI

GitHub Actions runs:

- `clang-format` verification for `src` and `include`
- CMake configure + Ninja build
- `cmake --install` to validate the install target
