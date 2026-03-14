#include "vmtrace/vmtrace.hpp"

#include <asmjit/x86.h>
#include <Windows.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace
{
    using std::string;

    constexpr std::uint64_t code_page_base = 0x1000;
    constexpr std::uint64_t output_page_base = 0x2000;
    constexpr std::uint64_t stack_page_base = 0x3000;
    constexpr std::uint64_t syscall_intercept_address = 0x4000;

    constexpr std::uint64_t cpuid_vendor_output_base = output_page_base;
    constexpr std::uint64_t syscall_return_output_base = output_page_base + 0x10;

    constexpr std::uint64_t syscall_number = 0x1234;
    constexpr std::uint64_t syscall_arg0 = 0x11111111;
    constexpr std::uint64_t syscall_arg1 = 0x22222222;
    constexpr std::uint64_t syscall_arg2 = 0x33333333;
    constexpr std::uint64_t syscall_arg3 = 0x44444444;
    constexpr std::uint64_t syscall_return_value = 0xFEEDFACECAFEBEEFull;

    class virtual_alloc_page
    {
      public:
        virtual_alloc_page()
            : page_(static_cast<std::uint8_t*>(::VirtualAlloc(nullptr, vmtrace::page_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)))
        {
            if (page_ == nullptr)
            {
                throw std::runtime_error("VirtualAlloc failed");
            }
        }

        virtual_alloc_page(const virtual_alloc_page&) = delete;
        virtual_alloc_page& operator=(const virtual_alloc_page&) = delete;

        ~virtual_alloc_page()
        {
            if (page_ != nullptr)
            {
                ::VirtualFree(page_, 0, MEM_RELEASE);
            }
        }

        std::uint8_t* data() const
        {
            return page_;
        }

      private:
        std::uint8_t* page_ = nullptr;
    };

    std::array<std::uint32_t, 3> vendor_to_registers(const std::string& vendor_string)
    {
        std::array<char, 12> padded_vendor = {};
        std::memcpy(padded_vendor.data(), vendor_string.data(), (std::min)(vendor_string.size(), padded_vendor.size()));

        std::array<std::uint32_t, 3> registers = {};
        std::memcpy(&registers[0], padded_vendor.data(), 4);
        std::memcpy(&registers[1], padded_vendor.data() + 4, 4);
        std::memcpy(&registers[2], padded_vendor.data() + 8, 4);
        return registers;
    }

    std::string vendor_from_memory(const std::uint8_t* data)
    {
        std::array<char, 13> vendor = {};
        std::memcpy(vendor.data(), data, 12);
        return {vendor.data(), 12};
    }

    struct sample_program
    {
        virtual_alloc_page code_page;
        virtual_alloc_page output_page;
        virtual_alloc_page stack_page;
        virtual_alloc_page syscall_page;
        std::string intercepted_vendor = "VmTraceLabs!";

        sample_program()
        {
            std::memset(code_page.data(), 0x90, vmtrace::page_size);
            std::memset(output_page.data(), 0x00, vmtrace::page_size);
            std::memset(stack_page.data(), 0x00, vmtrace::page_size);
            std::memset(syscall_page.data(), 0x90, vmtrace::page_size);
            syscall_page.data()[0] = 0xF4;

            auto code = build_code();
            std::memcpy(code_page.data(), code.data(), code.size());
        }

        std::vector<std::uint8_t> build_code() const
        {
            asmjit::CodeHolder code;

            code.init(asmjit::Environment::host(), asmjit::CpuInfo::host().features(), code_page_base);

            asmjit::x86::Assembler assembler(&code);
            using namespace asmjit::x86;

            assembler.xor_(eax, eax);
            assembler.xor_(ecx, ecx);
            assembler.cpuid();

            assembler.mov(rdi, cpuid_vendor_output_base);
            assembler.mov(dword_ptr(rdi), ebx);
            assembler.mov(dword_ptr(rdi, 4), edx);
            assembler.mov(dword_ptr(rdi, 8), ecx);

            assembler.mov(r10, syscall_arg0);
            assembler.mov(edx, static_cast<std::uint32_t>(syscall_arg1));
            assembler.mov(r8d, static_cast<std::uint32_t>(syscall_arg2));
            assembler.mov(r9d, static_cast<std::uint32_t>(syscall_arg3));
            assembler.mov(eax, static_cast<std::uint32_t>(syscall_number));

            assembler.syscall();

            assembler.mov(rdi, syscall_return_output_base);
            assembler.mov(qword_ptr(rdi), rax);
            assembler.hlt();

            code.flatten();

            std::vector<std::uint8_t> bytes(code.code_size());
            code.copy_flattened_data(bytes.data(), bytes.size(), asmjit::CopySectionFlags::kPadTargetBuffer);

            return bytes;
        }

        vmtrace::trap_response on_memory_trap(const vmtrace::trap_info& trap) const
        {
            std::cout << "Unexpected memory trap: access="
                      << ((trap.access_kind == vmtrace::trap_access_kind::read)    ? "read"
                          : (trap.access_kind == vmtrace::trap_access_kind::write) ? "write"
                                                                                   : "execute")
                      << " gpa=" << vmtrace::to_hex(trap.guest_physical_address) << " gva=" << vmtrace::to_hex(trap.guest_virtual_address)
                      << "\n";

            vmtrace::trap_response response = {};
            response.resolution = vmtrace::trap_resolution::stop_emulation;
            response.message = "Stopped on unexpected memory trap.";
            return response;
        }

        vmtrace::cpuid_response on_cpuid(const vmtrace::cpuid_info& info) const
        {
            std::cout << "Intercepted CPUID leaf=" << vmtrace::to_hex(info.leaf) << " subleaf=" << vmtrace::to_hex(info.subleaf) << "\n";

            if (info.leaf != 0 || info.subleaf != 0)
            {
                vmtrace::cpuid_response response = {};
                response.resolution = vmtrace::cpuid_resolution::passthrough;
                return response;
            }

            const auto vendor_registers = vendor_to_registers(intercepted_vendor);

            vmtrace::cpuid_response response = {};
            response.resolution = vmtrace::cpuid_resolution::emulate;
            response.eax = info.default_eax;
            response.ebx = vendor_registers[0];
            response.edx = vendor_registers[1];
            response.ecx = vendor_registers[2];
            response.message = "Replaced CPUID vendor string.";
            return response;
        }

        vmtrace::syscall_response on_syscall(const vmtrace::syscall_info& info) const
        {
            std::cout << "Intercepted syscall number=" << vmtrace::to_hex(info.number) << " arg0=" << vmtrace::to_hex(info.arg0)
                      << " arg1=" << vmtrace::to_hex(info.arg1) << " arg2=" << vmtrace::to_hex(info.arg2)
                      << " arg3=" << vmtrace::to_hex(info.arg3) << "\n";

            vmtrace::syscall_response response = {};
            response.resolution = vmtrace::syscall_resolution::emulate_and_return;
            response.return_value = syscall_return_value;
            response.message = "Returned a synthetic syscall result.";
            return response;
        }
    };
} // namespace

int main()
{
    try
    {
        std::cout << "Starting vmtrace demo\n";

        sample_program sample = {};

        vmtrace::emulator emulator({
            .memory_trap = [&sample](const vmtrace::trap_info& trap) { return sample.on_memory_trap(trap); },
            .cpuid = [&sample](const vmtrace::cpuid_info& info) { return sample.on_cpuid(info); },
            .syscall = [&sample](const vmtrace::syscall_info& info) { return sample.on_syscall(info); },
            .syscall_intercept_address = syscall_intercept_address,
        });

        emulator.map_memory({
            .host_address = sample.code_page.data(),
            .size = vmtrace::page_size,
            .access = vmtrace::map_access::read | vmtrace::map_access::execute,
            .guest_address = code_page_base,
        });

        emulator.map_memory({
            .host_address = sample.output_page.data(),
            .size = vmtrace::page_size,
            .access = vmtrace::map_access::read | vmtrace::map_access::write,
            .guest_address = output_page_base,
        });

        emulator.map_memory({
            .host_address = sample.stack_page.data(),
            .size = vmtrace::page_size,
            .access = vmtrace::map_access::read | vmtrace::map_access::write,
            .guest_address = stack_page_base,
        });

        emulator.map_memory({
            .host_address = sample.syscall_page.data(),
            .size = vmtrace::page_size,
            .access = vmtrace::map_access::read | vmtrace::map_access::execute,
            .guest_address = syscall_intercept_address,
        });

        vmtrace::cpu_state initial_state = {};
        initial_state.rip = code_page_base;
        initial_state.rsp = stack_page_base + vmtrace::page_size - 0x20;

        emulator.set_cpu_state(initial_state);
        emulator.run();

        const auto registers = emulator.read_registers();
        const auto vendor = vendor_from_memory(sample.output_page.data());
        std::uint64_t syscall_return = 0;
        std::memcpy(&syscall_return, sample.output_page.data() + 0x10, sizeof(syscall_return));

        std::cout << "Final registers\n";
        std::cout << "  RIP: " << vmtrace::to_hex(registers.rip) << "\n";
        std::cout << "  RAX: " << vmtrace::to_hex(registers.rax) << "\n";
        std::cout << "  RBX: " << vmtrace::to_hex(registers.rbx) << "\n";
        std::cout << "  RCX: " << vmtrace::to_hex(registers.rcx) << "\n";
        std::cout << "  RDX: " << vmtrace::to_hex(registers.rdx) << "\n";
        std::cout << "  RSP: " << vmtrace::to_hex(registers.rsp) << "\n";
        std::cout << "Vendor captured in guest memory: " << vendor << "\n";
        std::cout << "Syscall return captured in guest memory: " << vmtrace::to_hex(syscall_return) << "\n";

        return 0;
    }
    catch (const std::exception& exception)
    {
        std::cerr << "Error: " << exception.what() << "\n";
        return 1;
    }
}
