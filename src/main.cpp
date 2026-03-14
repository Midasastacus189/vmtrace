#include <Windows.h>
#include <WinHvPlatform.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>

namespace
{
constexpr UINT32 kVpIndex = 0;
constexpr WHV_GUEST_PHYSICAL_ADDRESS kGuestCodeGpa = 0x1000;
constexpr SIZE_T kGuestMemorySize = 0x1000;

// xor eax, eax; xor ecx, ecx; cpuid; hlt
constexpr std::array<std::uint8_t, 6> kGuestCode = {0x31, 0xC0, 0x31, 0xC9, 0x0F, 0xA2};
constexpr std::uint8_t kHltInstruction = 0xF4;

[[noreturn]] void ThrowIfFailed(HRESULT hr, const char* action)
{
    if (SUCCEEDED(hr))
    {
        throw std::logic_error("ThrowIfFailed called with success code");
    }

    std::ostringstream stream;
    stream << action << " failed with HRESULT 0x"
           << std::hex << std::setw(8) << std::setfill('0') << static_cast<unsigned long>(hr);
    throw std::runtime_error(stream.str());
}

void CheckHr(HRESULT hr, const char* action)
{
    if (FAILED(hr))
    {
        ThrowIfFailed(hr, action);
    }
}

WHV_X64_SEGMENT_REGISTER MakeCodeSegment()
{
    WHV_X64_SEGMENT_REGISTER segment = {};
    segment.Base = 0;
    segment.Limit = 0xFFFFF;
    segment.Selector = 0x8;
    segment.SegmentType = 0xB;
    segment.NonSystemSegment = 1;
    segment.DescriptorPrivilegeLevel = 0;
    segment.Present = 1;
    segment.Long = 0;
    segment.Default = 1;
    segment.Granularity = 1;
    return segment;
}

WHV_X64_SEGMENT_REGISTER MakeDataSegment()
{
    WHV_X64_SEGMENT_REGISTER segment = {};
    segment.Base = 0;
    segment.Limit = 0xFFFFF;
    segment.Selector = 0x10;
    segment.SegmentType = 0x3;
    segment.NonSystemSegment = 1;
    segment.DescriptorPrivilegeLevel = 0;
    segment.Present = 1;
    segment.Long = 0;
    segment.Default = 1;
    segment.Granularity = 1;
    return segment;
}

std::array<UINT32, 3> EncodeVendorString(std::string_view vendor)
{
    std::array<char, 12> padded = {};
    const size_t count = (vendor.size() < padded.size()) ? vendor.size() : padded.size();
    std::memcpy(padded.data(), vendor.data(), count);

    std::array<UINT32, 3> encoded = {};
    std::memcpy(&encoded[0], padded.data() + 0, sizeof(UINT32));
    std::memcpy(&encoded[1], padded.data() + 4, sizeof(UINT32));
    std::memcpy(&encoded[2], padded.data() + 8, sizeof(UINT32));
    return encoded;
}

std::string DecodeVendorString(UINT32 ebx, UINT32 edx, UINT32 ecx)
{
    std::array<char, 13> vendor = {};
    std::memcpy(vendor.data() + 0, &ebx, sizeof(UINT32));
    std::memcpy(vendor.data() + 4, &edx, sizeof(UINT32));
    std::memcpy(vendor.data() + 8, &ecx, sizeof(UINT32));
    vendor[12] = '\0';
    return std::string(vendor.data());
}

class VirtualAllocBuffer
{
public:
    explicit VirtualAllocBuffer(SIZE_T size)
        : size_(size)
        , ptr_(::VirtualAlloc(nullptr, size_, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))
    {
        if (ptr_ == nullptr)
        {
            throw std::runtime_error("VirtualAlloc failed");
        }
    }

    ~VirtualAllocBuffer()
    {
        if (ptr_ != nullptr)
        {
            ::VirtualFree(ptr_, 0, MEM_RELEASE);
        }
    }

    VirtualAllocBuffer(const VirtualAllocBuffer&) = delete;
    VirtualAllocBuffer& operator=(const VirtualAllocBuffer&) = delete;

    void* data() const
    {
        return ptr_;
    }

    SIZE_T size() const
    {
        return size_;
    }

private:
    SIZE_T size_;
    void* ptr_;
};

class PartitionHandle
{
public:
    PartitionHandle()
    {
        CheckHr(WHvCreatePartition(&handle_), "WHvCreatePartition");
    }

    ~PartitionHandle()
    {
        if (handle_ != nullptr)
        {
            WHvDeletePartition(handle_);
        }
    }

    PartitionHandle(const PartitionHandle&) = delete;
    PartitionHandle& operator=(const PartitionHandle&) = delete;

    WHV_PARTITION_HANDLE get() const
    {
        return handle_;
    }

private:
    WHV_PARTITION_HANDLE handle_ = nullptr;
};

class VirtualProcessorHandle
{
public:
    VirtualProcessorHandle(WHV_PARTITION_HANDLE partition, UINT32 vpIndex)
        : partition_(partition)
        , vpIndex_(vpIndex)
    {
        CheckHr(WHvCreateVirtualProcessor(partition_, vpIndex_, 0), "WHvCreateVirtualProcessor");
    }

    ~VirtualProcessorHandle()
    {
        if (partition_ != nullptr)
        {
            WHvDeleteVirtualProcessor(partition_, vpIndex_);
        }
    }

    VirtualProcessorHandle(const VirtualProcessorHandle&) = delete;
    VirtualProcessorHandle& operator=(const VirtualProcessorHandle&) = delete;

private:
    WHV_PARTITION_HANDLE partition_ = nullptr;
    UINT32 vpIndex_ = 0;
};

void ConfigurePartition(WHV_PARTITION_HANDLE partition)
{
    UINT32 processorCount = 1;
    CheckHr(
        WHvSetPartitionProperty(
            partition,
            WHvPartitionPropertyCodeProcessorCount,
            &processorCount,
            sizeof(processorCount)),
        "WHvSetPartitionProperty(ProcessorCount)");

    WHV_EXTENDED_VM_EXITS exits = {};
    exits.X64CpuidExit = 1;
    CheckHr(
        WHvSetPartitionProperty(
            partition,
            WHvPartitionPropertyCodeExtendedVmExits,
            &exits,
            sizeof(exits)),
        "WHvSetPartitionProperty(ExtendedVmExits)");

    const UINT32 cpuidLeaf = 0;
    CheckHr(
        WHvSetPartitionProperty(
            partition,
            WHvPartitionPropertyCodeCpuidExitList,
            &cpuidLeaf,
            sizeof(cpuidLeaf)),
        "WHvSetPartitionProperty(CpuidExitList)");

    CheckHr(WHvSetupPartition(partition), "WHvSetupPartition");
}

void InitializeRegisters(WHV_PARTITION_HANDLE partition)
{
    const std::array<WHV_REGISTER_NAME, 11> names = {
        WHvX64RegisterRip,
        WHvX64RegisterRflags,
        WHvX64RegisterCs,
        WHvX64RegisterDs,
        WHvX64RegisterEs,
        WHvX64RegisterFs,
        WHvX64RegisterGs,
        WHvX64RegisterSs,
        WHvX64RegisterCr0,
        WHvX64RegisterCr4,
        WHvX64RegisterEfer,
    };

    std::array<WHV_REGISTER_VALUE, names.size()> values = {};
    values[0].Reg64 = kGuestCodeGpa;
    values[1].Reg64 = 0x2;
    values[2].Segment = MakeCodeSegment();

    const WHV_X64_SEGMENT_REGISTER dataSegment = MakeDataSegment();
    values[3].Segment = dataSegment;
    values[4].Segment = dataSegment;
    values[5].Segment = dataSegment;
    values[6].Segment = dataSegment;
    values[7].Segment = dataSegment;
    values[8].Reg64 = 0x1;
    values[9].Reg64 = 0x0;
    values[10].Reg64 = 0x0;

    CheckHr(
        WHvSetVirtualProcessorRegisters(
            partition,
            kVpIndex,
            names.data(),
            static_cast<UINT32>(names.size()),
            values.data()),
        "WHvSetVirtualProcessorRegisters(initial)");
}

void WriteGuestCode(void* guestMemory)
{
    std::memset(guestMemory, 0x90, kGuestMemorySize);
    std::memcpy(guestMemory, kGuestCode.data(), kGuestCode.size());
    static_cast<std::uint8_t*>(guestMemory)[kGuestCode.size()] = kHltInstruction;
}

void EnsurePlatformSupportsCpuidExits()
{
    BOOL hypervisorPresent = FALSE;
    UINT32 bytesWritten = 0;
    CheckHr(
        WHvGetCapability(
            WHvCapabilityCodeHypervisorPresent,
            &hypervisorPresent,
            sizeof(hypervisorPresent),
            &bytesWritten),
        "WHvGetCapability(HypervisorPresent)");

    if (!hypervisorPresent)
    {
        throw std::runtime_error("The Windows hypervisor is not present. Enable Hyper-V and Windows Hypervisor Platform.");
    }

    WHV_EXTENDED_VM_EXITS exits = {};
    CheckHr(
        WHvGetCapability(
            WHvCapabilityCodeExtendedVmExits,
            &exits,
            sizeof(exits),
            &bytesWritten),
        "WHvGetCapability(ExtendedVmExits)");

    if (!exits.X64CpuidExit)
    {
        throw std::runtime_error("This host does not report WHP CPUID-exit support.");
    }
}

void AdvanceRipAfterExit(WHV_PARTITION_HANDLE partition, const WHV_RUN_VP_EXIT_CONTEXT& exitContext)
{
    const WHV_REGISTER_NAME name = WHvX64RegisterRip;
    WHV_REGISTER_VALUE value = {};
    value.Reg64 = exitContext.VpContext.Rip + exitContext.VpContext.InstructionLength;

    CheckHr(
        WHvSetVirtualProcessorRegisters(partition, kVpIndex, &name, 1, &value),
        "WHvSetVirtualProcessorRegisters(RIP)");
}

void SetCpuidResult(
    WHV_PARTITION_HANDLE partition,
    UINT32 eax,
    UINT32 ebx,
    UINT32 ecx,
    UINT32 edx)
{
    const std::array<WHV_REGISTER_NAME, 4> names = {
        WHvX64RegisterRax,
        WHvX64RegisterRbx,
        WHvX64RegisterRcx,
        WHvX64RegisterRdx,
    };

    std::array<WHV_REGISTER_VALUE, names.size()> values = {};
    values[0].Reg64 = eax;
    values[1].Reg64 = ebx;
    values[2].Reg64 = ecx;
    values[3].Reg64 = edx;

    CheckHr(
        WHvSetVirtualProcessorRegisters(
            partition,
            kVpIndex,
            names.data(),
            static_cast<UINT32>(names.size()),
            values.data()),
        "WHvSetVirtualProcessorRegisters(CPUID result)");
}

void PrintFinalRegisters(WHV_PARTITION_HANDLE partition)
{
    const std::array<WHV_REGISTER_NAME, 4> names = {
        WHvX64RegisterRax,
        WHvX64RegisterRbx,
        WHvX64RegisterRcx,
        WHvX64RegisterRdx,
    };

    std::array<WHV_REGISTER_VALUE, names.size()> values = {};
    CheckHr(
        WHvGetVirtualProcessorRegisters(
            partition,
            kVpIndex,
            names.data(),
            static_cast<UINT32>(names.size()),
            values.data()),
        "WHvGetVirtualProcessorRegisters(final)");

    const UINT32 eax = static_cast<UINT32>(values[0].Reg64);
    const UINT32 ebx = static_cast<UINT32>(values[1].Reg64);
    const UINT32 ecx = static_cast<UINT32>(values[2].Reg64);
    const UINT32 edx = static_cast<UINT32>(values[3].Reg64);

    std::cout << "Final guest-visible CPUID leaf 0 values\n";
    std::cout << "  EAX: 0x" << std::hex << eax << "\n";
    std::cout << "  EBX: 0x" << std::hex << ebx << "\n";
    std::cout << "  ECX: 0x" << std::hex << ecx << "\n";
    std::cout << "  EDX: 0x" << std::hex << edx << "\n";
    std::cout << "  Vendor: " << DecodeVendorString(ebx, edx, ecx) << "\n";
}

void RunDemo(std::string_view spoofedVendor)
{
    EnsurePlatformSupportsCpuidExits();

    PartitionHandle partition;
    ConfigurePartition(partition.get());

    VirtualAllocBuffer guestMemory(kGuestMemorySize);
    WriteGuestCode(guestMemory.data());

    CheckHr(
        WHvMapGpaRange(
            partition.get(),
            guestMemory.data(),
            kGuestCodeGpa,
            guestMemory.size(),
            WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite | WHvMapGpaRangeFlagExecute),
        "WHvMapGpaRange");

    VirtualProcessorHandle virtualProcessor(partition.get(), kVpIndex);
    InitializeRegisters(partition.get());

    const std::array<UINT32, 3> vendor = EncodeVendorString(spoofedVendor);
    bool halted = false;
    bool cpuidIntercepted = false;

    while (!halted)
    {
        WHV_RUN_VP_EXIT_CONTEXT exitContext = {};
        CheckHr(
            WHvRunVirtualProcessor(
                partition.get(),
                kVpIndex,
                &exitContext,
                sizeof(exitContext)),
            "WHvRunVirtualProcessor");

        switch (exitContext.ExitReason)
        {
        case WHvRunVpExitReasonX64Cpuid:
        {
            cpuidIntercepted = true;
            const auto& cpuid = exitContext.CpuidAccess;

            std::cout << "Intercepted CPUID leaf 0x" << std::hex << cpuid.Rax
                      << ", subleaf 0x" << cpuid.Rcx << "\n";
            std::cout << "  Default vendor: "
                      << DecodeVendorString(
                             static_cast<UINT32>(cpuid.DefaultResultRbx),
                             static_cast<UINT32>(cpuid.DefaultResultRdx),
                             static_cast<UINT32>(cpuid.DefaultResultRcx))
                      << "\n";

            SetCpuidResult(
                partition.get(),
                static_cast<UINT32>(cpuid.DefaultResultRax),
                vendor[0],
                vendor[2],
                vendor[1]);

            AdvanceRipAfterExit(partition.get(), exitContext);
            break;
        }
        case WHvRunVpExitReasonX64Halt:
            halted = true;
            break;
        default:
        {
            std::ostringstream stream;
            stream << "Unexpected VP exit reason: 0x" << std::hex << exitContext.ExitReason;
            throw std::runtime_error(stream.str());
        }
        }
    }

    if (!cpuidIntercepted)
    {
        throw std::runtime_error("Guest halted without triggering a CPUID exit.");
    }

    PrintFinalRegisters(partition.get());
}
} // namespace

int main(int argc, char** argv)
{
    try
    {
        const std::string spoofedVendor = (argc > 1) ? argv[1] : "OpenAI  Lab";

        std::cout << "Starting WHP CPUID interception demo\n";
        std::cout << "Requested vendor string: " << spoofedVendor << "\n";

        RunDemo(spoofedVendor);
        return 0;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "Error: " << ex.what() << "\n";
        return 1;
    }
}
