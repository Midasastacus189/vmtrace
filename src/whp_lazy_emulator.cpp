#include "whp_lazy_emulator/whp_lazy_emulator.hpp"

#include <WinHvPlatform.h>

#include <array>
#include <cstring>
#include <iomanip>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <unordered_map>

namespace whp_lazy_emulator
{
namespace
{
constexpr UINT32 vp_index = 0;

struct mapped_page
{
    struct virtual_free_deleter
    {
        void operator()(std::uint8_t* page) const
        {
            if (page != nullptr)
            {
                ::VirtualFree(page, 0, MEM_RELEASE);
            }
        }
    };

    void* host_page = nullptr;
    UINT32 map_flags = 0;
    std::unique_ptr<std::uint8_t, virtual_free_deleter> owned_page;
};

[[noreturn]] void throw_hr(HRESULT hr, const char* action)
{
    std::ostringstream stream;
    stream << action << " failed with HRESULT 0x"
           << std::hex << std::setw(8) << std::setfill('0') << static_cast<unsigned long>(hr);
    throw std::runtime_error(stream.str());
}

void check_hr(HRESULT hr, const char* action)
{
    if (FAILED(hr))
    {
        throw_hr(hr, action);
    }
}

class partition_handle
{
public:
    partition_handle()
    {
        check_hr(WHvCreatePartition(&handle_), "WHvCreatePartition");
    }

    partition_handle(const partition_handle&) = delete;
    partition_handle& operator=(const partition_handle&) = delete;

    ~partition_handle()
    {
        if (handle_ != nullptr)
        {
            WHvDeletePartition(handle_);
        }
    }

    WHV_PARTITION_HANDLE get() const
    {
        return handle_;
    }

private:
    WHV_PARTITION_HANDLE handle_ = nullptr;
};

class virtual_processor_handle
{
public:
    explicit virtual_processor_handle(WHV_PARTITION_HANDLE partition)
        : partition_(partition)
    {
        check_hr(WHvCreateVirtualProcessor(partition_, vp_index, 0), "WHvCreateVirtualProcessor");
    }

    virtual_processor_handle(const virtual_processor_handle&) = delete;
    virtual_processor_handle& operator=(const virtual_processor_handle&) = delete;

    ~virtual_processor_handle()
    {
        if (partition_ != nullptr)
        {
            WHvDeleteVirtualProcessor(partition_, vp_index);
        }
    }

private:
    WHV_PARTITION_HANDLE partition_ = nullptr;
};

trap_access_kind access_kind_from_whp(WHV_MEMORY_ACCESS_TYPE access_type)
{
    switch (access_type)
    {
    case WHvMemoryAccessRead:
        return trap_access_kind::read;
    case WHvMemoryAccessWrite:
        return trap_access_kind::write;
    case WHvMemoryAccessExecute:
        return trap_access_kind::execute;
    default:
        throw std::runtime_error("Unknown WHP memory access type.");
    }
}

UINT32 normalize_map_flags(UINT32 map_flags)
{
    if ((map_flags & (WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite | WHvMapGpaRangeFlagExecute)) == 0)
    {
        throw std::runtime_error("Mapped page needs at least one access flag.");
    }

    return map_flags;
}

UINT32 to_whp_map_flags(map_access access)
{
    UINT32 flags = 0;

    if ((access & map_access::read) != map_access::none)
    {
        flags |= WHvMapGpaRangeFlagRead;
    }

    if ((access & map_access::write) != map_access::none)
    {
        flags |= WHvMapGpaRangeFlagWrite;
    }

    if ((access & map_access::execute) != map_access::none)
    {
        flags |= WHvMapGpaRangeFlagExecute;
    }

    return normalize_map_flags(flags);
}

WHV_X64_SEGMENT_REGISTER make_code_segment()
{
    WHV_X64_SEGMENT_REGISTER segment = {};
    segment.Base = 0;
    segment.Limit = 0xFFFFF;
    segment.Selector = 0x8;
    segment.SegmentType = 0xB;
    segment.NonSystemSegment = 1;
    segment.DescriptorPrivilegeLevel = 0;
    segment.Present = 1;
    segment.Default = 1;
    segment.Granularity = 1;
    return segment;
}

WHV_X64_SEGMENT_REGISTER make_data_segment()
{
    WHV_X64_SEGMENT_REGISTER segment = {};
    segment.Base = 0;
    segment.Limit = 0xFFFFF;
    segment.Selector = 0x10;
    segment.SegmentType = 0x3;
    segment.NonSystemSegment = 1;
    segment.DescriptorPrivilegeLevel = 0;
    segment.Present = 1;
    segment.Default = 1;
    segment.Granularity = 1;
    return segment;
}

trap_info build_trap_info(const WHV_MEMORY_ACCESS_CONTEXT& memory_access)
{
    trap_info info = {};
    info.access_kind = access_kind_from_whp(static_cast<WHV_MEMORY_ACCESS_TYPE>(memory_access.AccessInfo.AccessType));
    info.guest_physical_address = memory_access.Gpa;
    info.guest_virtual_address = memory_access.Gva;
    info.guest_virtual_address_valid = memory_access.AccessInfo.GvaValid != 0;
    info.instruction_bytes.assign(
        memory_access.InstructionBytes,
        memory_access.InstructionBytes + memory_access.InstructionByteCount);
    return info;
}
} // namespace

class emulator::implementation
{
public:
    explicit implementation(trap_handler trap_handler_callback)
        : trap_handler_(std::move(trap_handler_callback))
    {
        ensure_platform_support();
        configure_partition();
        virtual_processor_ = std::make_unique<virtual_processor_handle>(partition_.get());
    }

    void set_cpu_state(const cpu_state& state)
    {
        const std::array<WHV_REGISTER_NAME, 19> names = {
            WHvX64RegisterRip,
            WHvX64RegisterRsp,
            WHvX64RegisterRflags,
            WHvX64RegisterRax,
            WHvX64RegisterRbx,
            WHvX64RegisterRcx,
            WHvX64RegisterRdx,
            WHvX64RegisterRsi,
            WHvX64RegisterRdi,
            WHvX64RegisterRbp,
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
        values[0].Reg64 = state.rip;
        values[1].Reg64 = state.rsp;
        values[2].Reg64 = state.rflags;
        values[3].Reg64 = state.rax;
        values[4].Reg64 = state.rbx;
        values[5].Reg64 = state.rcx;
        values[6].Reg64 = state.rdx;
        values[7].Reg64 = state.rsi;
        values[8].Reg64 = state.rdi;
        values[9].Reg64 = state.rbp;

        const WHV_X64_SEGMENT_REGISTER code_segment = make_code_segment();
        const WHV_X64_SEGMENT_REGISTER data_segment = make_data_segment();

        values[10].Segment = code_segment;
        values[11].Segment = data_segment;
        values[12].Segment = data_segment;
        values[13].Segment = data_segment;
        values[14].Segment = data_segment;
        values[15].Segment = data_segment;
        values[16].Reg64 = 0x1;
        values[17].Reg64 = 0x0;
        values[18].Reg64 = 0x0;

        check_hr(
            WHvSetVirtualProcessorRegisters(
                partition_.get(),
                vp_index,
                names.data(),
                static_cast<UINT32>(names.size()),
                values.data()),
            "WHvSetVirtualProcessorRegisters");
    }

    void map_memory(const mapped_range& range)
    {
        if (range.host_address == nullptr)
        {
            throw std::runtime_error("map_memory requires a valid host address.");
        }

        if (range.size == 0)
        {
            throw std::runtime_error("map_memory requires a non-zero size.");
        }

        if (!is_page_aligned(reinterpret_cast<std::uint64_t>(range.host_address)))
        {
            throw std::runtime_error("Host address must be page aligned.");
        }

        if (!is_page_aligned(range.size))
        {
            throw std::runtime_error("Mapped size must be page aligned.");
        }

        const std::uint64_t guest_address = range.guest_address.value_or(reinterpret_cast<std::uint64_t>(range.host_address));
        if (!is_page_aligned(guest_address))
        {
            throw std::runtime_error("Guest address must be page aligned.");
        }

        const UINT32 map_flags = to_whp_map_flags(range.access);

        trap_response response = {};
        response.resolution = trap_resolution::map_page;
        response.access = range.access;
        response.host_page = range.host_address;

        for (std::size_t offset = 0; offset < range.size; offset += page_size)
        {
            const auto current_guest_address = guest_address + offset;
            const auto current_host_address =
                static_cast<void*>(static_cast<std::uint8_t*>(range.host_address) + offset);
            response.host_page = current_host_address;
            map_page(current_guest_address, response, map_flags);
        }
    }

    void run()
    {
        bool running = true;

        while (running)
        {
            WHV_RUN_VP_EXIT_CONTEXT exit_context = {};
            check_hr(
                WHvRunVirtualProcessor(partition_.get(), vp_index, &exit_context, sizeof(exit_context)),
                "WHvRunVirtualProcessor");

            switch (exit_context.ExitReason)
            {
            case WHvRunVpExitReasonMemoryAccess:
                handle_memory_access(exit_context.MemoryAccess, running);
                break;
            case WHvRunVpExitReasonException:
                handle_exception(exit_context);
                running = false;
                break;
            case WHvRunVpExitReasonUnsupportedFeature:
                handle_unsupported_feature(exit_context);
                running = false;
                break;
            case WHvRunVpExitReasonX64Halt:
                running = false;
                break;
            default:
            {
                std::ostringstream stream;
                stream << "Unexpected exit reason: 0x" << std::hex << exit_context.ExitReason;
                throw std::runtime_error(stream.str());
            }
            }
        }
    }

    register_snapshot read_registers() const
    {
        const std::array<WHV_REGISTER_NAME, 6> names = {
            WHvX64RegisterRip,
            WHvX64RegisterRax,
            WHvX64RegisterRbx,
            WHvX64RegisterRcx,
            WHvX64RegisterRdx,
            WHvX64RegisterRsp,
        };

        std::array<WHV_REGISTER_VALUE, names.size()> values = {};
        check_hr(
            WHvGetVirtualProcessorRegisters(
                partition_.get(),
                vp_index,
                names.data(),
                static_cast<UINT32>(names.size()),
                values.data()),
            "WHvGetVirtualProcessorRegisters");

        return {
            values[0].Reg64,
            values[1].Reg64,
            values[2].Reg64,
            values[3].Reg64,
            values[4].Reg64,
            values[5].Reg64,
        };
    }

private:
    void ensure_platform_support()
    {
        BOOL hypervisor_present = FALSE;
        UINT32 bytes_written = 0;

        check_hr(
            WHvGetCapability(
                WHvCapabilityCodeHypervisorPresent,
                &hypervisor_present,
                sizeof(hypervisor_present),
                &bytes_written),
            "WHvGetCapability(HypervisorPresent)");

        if (!hypervisor_present)
        {
            throw std::runtime_error("Hypervisor is not present. Enable Hyper-V and Windows Hypervisor Platform.");
        }

        check_hr(
            WHvGetCapability(
                WHvCapabilityCodeExtendedVmExits,
                &supported_exits_,
                sizeof(supported_exits_),
                &bytes_written),
            "WHvGetCapability(ExtendedVmExits)");
    }

    void configure_partition()
    {
        UINT32 processor_count = 1;
        check_hr(
            WHvSetPartitionProperty(
                partition_.get(),
                WHvPartitionPropertyCodeProcessorCount,
                &processor_count,
                sizeof(processor_count)),
            "WHvSetPartitionProperty(ProcessorCount)");

        WHV_EXTENDED_VM_EXITS enabled_exits = {};
        enabled_exits.ExceptionExit = supported_exits_.ExceptionExit ? 1 : 0;

        check_hr(
            WHvSetPartitionProperty(
                partition_.get(),
                WHvPartitionPropertyCodeExtendedVmExits,
                &enabled_exits,
                sizeof(enabled_exits)),
            "WHvSetPartitionProperty(ExtendedVmExits)");

        check_hr(WHvSetupPartition(partition_.get()), "WHvSetupPartition");
    }

    void handle_memory_access(const WHV_MEMORY_ACCESS_CONTEXT& memory_access, bool& running)
    {
        const trap_response response = trap_handler_(build_trap_info(memory_access));

        switch (response.resolution)
        {
        case trap_resolution::map_page:
            map_page(memory_access.Gpa, response);
            break;
        case trap_resolution::stop_emulation:
            running = false;
            break;
        case trap_resolution::deny_access:
            throw std::runtime_error("Trap handler denied access.");
        }
    }

    void map_page(std::uint64_t guest_physical_address, const trap_response& response)
    {
        map_page(guest_physical_address, response, to_whp_map_flags(response.access));
    }

    void map_page(std::uint64_t guest_physical_address, const trap_response& response, UINT32 map_flags)
    {
        const std::uint64_t page_base = align_down_to_page(guest_physical_address);

        auto& page = mapped_pages_[page_base];
        if (!page)
        {
            page = std::make_unique<mapped_page>();
        }

        if (page->host_page == nullptr)
        {
            if (response.host_page != nullptr)
            {
                page->host_page = response.host_page;
            }
            else
            {
                auto raw_page = static_cast<std::uint8_t*>(::VirtualAlloc(nullptr, page_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
                if (raw_page == nullptr)
                {
                    throw std::runtime_error("VirtualAlloc failed while backing a guest page.");
                }

                std::memset(raw_page, 0, page_size);
                if (!response.page_bytes.empty())
                {
                    std::memcpy(raw_page, response.page_bytes.data(), (std::min)(response.page_bytes.size(), static_cast<size_t>(page_size)));
                }

                page->owned_page.reset(raw_page);
                page->host_page = raw_page;
            }
        }

        if (page->map_flags != 0)
        {
            check_hr(WHvUnmapGpaRange(partition_.get(), page_base, page_size), "WHvUnmapGpaRange");
        }

        page->map_flags |= map_flags;

        check_hr(
            WHvMapGpaRange(
                partition_.get(),
                page->host_page,
                page_base,
                page_size,
                static_cast<WHV_MAP_GPA_RANGE_FLAGS>(page->map_flags)),
            "WHvMapGpaRange");
    }

    void handle_exception(const WHV_RUN_VP_EXIT_CONTEXT& exit_context)
    {
        const auto& exception = exit_context.VpException;
        std::ostringstream stream;
        stream << "Guest exception type=0x" << std::hex << static_cast<unsigned>(exception.ExceptionType)
               << " rip=0x" << exit_context.VpContext.Rip;
        throw std::runtime_error(stream.str());
    }

    void handle_unsupported_feature(const WHV_RUN_VP_EXIT_CONTEXT& exit_context)
    {
        const auto& unsupported_feature = exit_context.UnsupportedFeature;
        std::ostringstream stream;
        stream << "Unsupported feature exit. code=0x" << std::hex << unsupported_feature.FeatureCode
               << " rip=0x" << exit_context.VpContext.Rip;
        throw std::runtime_error(stream.str());
    }

    partition_handle partition_;
    std::unique_ptr<virtual_processor_handle> virtual_processor_;
    trap_handler trap_handler_;
    WHV_EXTENDED_VM_EXITS supported_exits_ = {};
    std::unordered_map<std::uint64_t, std::unique_ptr<mapped_page>> mapped_pages_;
};

emulator::emulator(trap_handler trap_handler_callback)
    : implementation_(std::make_unique<implementation>(std::move(trap_handler_callback)))
{
}

emulator::~emulator() = default;
emulator::emulator(emulator&&) noexcept = default;
emulator& emulator::operator=(emulator&&) noexcept = default;

void emulator::set_cpu_state(const cpu_state& state)
{
    implementation_->set_cpu_state(state);
}

void emulator::map_memory(const mapped_range& range)
{
    implementation_->map_memory(range);
}

void emulator::run()
{
    implementation_->run();
}

register_snapshot emulator::read_registers() const
{
    return implementation_->read_registers();
}

std::uint64_t align_down_to_page(std::uint64_t value)
{
    return value & ~(page_size - 1);
}

bool is_page_aligned(std::uint64_t value)
{
    return (value % page_size) == 0;
}

map_access operator|(map_access left, map_access right)
{
    return static_cast<map_access>(static_cast<std::uint32_t>(left) | static_cast<std::uint32_t>(right));
}

map_access operator&(map_access left, map_access right)
{
    return static_cast<map_access>(static_cast<std::uint32_t>(left) & static_cast<std::uint32_t>(right));
}

map_access& operator|=(map_access& left, map_access right)
{
    left = left | right;
    return left;
}

std::string to_hex(std::uint64_t value)
{
    std::ostringstream stream;
    stream << "0x" << std::hex << value;
    return stream.str();
}
} // namespace whp_lazy_emulator
