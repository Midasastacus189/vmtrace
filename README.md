# vmtrace

`vmtrace` is a small Windows Hypervisor Platform library for running a virtual CPU from a supplied CPU state and reacting to traps as they occur.

The core library is built as a static library, and the repository also includes a tiny `vmtrace_demo` executable that shows lazy page mapping in action.

## What it does

- Accepts an initial x64 CPU state
- Starts execution from the supplied `RIP`
- Traps page-level memory read, write, and execute faults
- Lets the host decide whether to map memory, deny access, or stop emulation
- Supports host-backed guest memory mappings
- Exposes optional `CPUID` and syscall interception hooks

This keeps the project small, but still useful for research around lazy memory mapping, instruction exits, and controlled guest execution.

## Prerequisites

On the host, enable these Windows features:

- `Microsoft-Hyper-V-Hypervisor`
- `HypervisorPlatform`

On many systems this effectively means enabling Hyper-V and Windows Hypervisor Platform in "Turn Windows features on or off", then rebooting.

## Build

Use a shell where MSVC is available, such as `x64 Native Tools Command Prompt for VS`:

```powershell
cmake -S . -B build -G "Ninja"
cmake --build build
```

## Run

```powershell
.\build\vmtrace_demo.exe
```

The demo accepts one optional flag:

```powershell
.\build\vmtrace_demo.exe --stop-on-tail-execute
```

Without the flag, the demo lazily maps a final execute page and halts. With the flag, it stops when that execute trap occurs.

## Install

`vmtrace` supports `cmake --install` and exports a CMake package:

```powershell
cmake --install build --prefix .\build\install
```

After installation, consumers can use:

```cmake
find_package(vmtrace CONFIG REQUIRED)
target_link_libraries(your_target PRIVATE vmtrace::vmtrace)
```

## Expected output

You should see output similar to:

```text
Starting vmtrace demo
Trap: read gpa=0x2000 gva=0x2000 source=0x2000
Trap: write gpa=0x3000 gva=0x3000 source=0x3000
Trap: execute gpa=0x4000 gva=0x4000 source=0x4000
Final registers
  RIP: 0x...
  RAX: 0x...
  RBX: 0x...
  RCX: 0x...
  RDX: 0x...
  RSP: 0x...
Host-backed write page value: 0x12345678
```

## Good next steps

- Add richer register access helpers to the public API
- Expand `CPUID` interception to configurable leaf lists
- Add a more explicit syscall interception demo
- Support larger lazy-mapped regions in trap callbacks
- Add tests around install/package consumption
