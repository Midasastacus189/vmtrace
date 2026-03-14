# Windows Hypervisor Platform CPUID Intercept Demo

This project creates a tiny guest with the Windows Hypervisor Platform (WHP), traps a `CPUID` instruction, and rewrites the returned vendor string before the guest resumes.

## What it does

- Creates a WHP partition with one virtual processor
- Enables `CPUID` exits for leaf `0`
- Maps a single guest page containing this code:

```asm
xor eax, eax
xor ecx, ecx
cpuid
hlt
```

- Intercepts the `CPUID` VM-exit in the host
- Replaces the vendor string registers (`EBX`, `EDX`, `ECX`)
- Resumes execution until the guest halts

This is intentionally small so it is easy to extend into deeper research on exit handling, instruction emulation, register inspection, or tracing.

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

If you prefer Visual Studio generators:

```powershell
cmake -S . -B build
cmake --build build --config Release
```

## Run

```powershell
.\build\whp_cpuid_spoof.exe
```

Optionally pass a custom 12-byte vendor string:

```powershell
.\build\whp_cpuid_spoof.exe "ResearchLab!"
```

Strings shorter than 12 bytes are zero-padded. Longer strings are truncated to 12 bytes.

## Expected output

You should see output similar to:

```text
Starting WHP CPUID interception demo
Requested vendor string: OpenAI  Lab
Intercepted CPUID leaf 0x0, subleaf 0x0
  Default vendor: GenuineIntel
Final guest-visible CPUID leaf 0 values
  EAX: 0x...
  EBX: 0x...
  ECX: 0x...
  EDX: 0x...
  Vendor: OpenAI  Lab
```

## Good next steps

- Add more intercepted leaves like `1`, `7`, and `0x40000000`
- Log all exits with timestamps
- Inject synthetic CPU feature bits for differential testing
- Move from a toy guest to a small boot stub with shared-memory reporting
- Explore `MSR` and `MMIO` exits alongside `CPUID`
