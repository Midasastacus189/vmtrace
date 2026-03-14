#include "whp_lazy_emulator/whp_lazy_emulator.hpp"

#include <Windows.h>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>

namespace
{
    constexpr std::uint64_t code_page_base = 0x1000;
    constexpr std::uint64_t read_page_base = 0x2000;
    constexpr std::uint64_t write_page_base = 0x3000;
    constexpr std::uint64_t tail_code_page_base = 0x4000;

    class virtual_alloc_page
    {
      public:
        virtual_alloc_page()
            : page_(static_cast<std::uint8_t*>(
                  ::VirtualAlloc(nullptr, whp_lazy_emulator::page_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)))
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

    struct sample_memory
    {
        virtual_alloc_page code_page;
        virtual_alloc_page read_page;
        virtual_alloc_page write_page;
        virtual_alloc_page tail_code_page;

        explicit sample_memory(bool stop_on_tail_execute)
            : stop_on_tail_execute(stop_on_tail_execute)
        {
            std::memset(code_page.data(), 0x90, whp_lazy_emulator::page_size);
            std::memset(read_page.data(), 0x00, whp_lazy_emulator::page_size);
            std::memset(write_page.data(), 0x00, whp_lazy_emulator::page_size);
            std::memset(tail_code_page.data(), 0x90, whp_lazy_emulator::page_size);

            code_page.data()[0] = 0xA1;
            std::memcpy(code_page.data() + 1, &read_page_target, sizeof(read_page_target));

            code_page.data()[5] = 0xA3;
            std::memcpy(code_page.data() + 6, &write_page_target, sizeof(write_page_target));

            code_page.data()[10] = 0xE9;
            const auto relative_jump = static_cast<std::int32_t>(tail_code_page_base - (code_page_base + 15));
            std::memcpy(code_page.data() + 11, &relative_jump, sizeof(relative_jump));

            tail_code_page.data()[0] = 0xF4;

            const std::uint32_t value = 0x12345678;
            std::memcpy(read_page.data(), &value, sizeof(value));
        }

        whp_lazy_emulator::trap_response on_trap(const whp_lazy_emulator::trap_info& trap) const
        {
            const std::uint64_t page_base = whp_lazy_emulator::align_down_to_page(trap.guest_physical_address);

            std::cout << "Trap: "
                      << ((trap.access_kind == whp_lazy_emulator::trap_access_kind::read)    ? "read"
                          : (trap.access_kind == whp_lazy_emulator::trap_access_kind::write) ? "write"
                                                                                             : "execute")
                      << " gpa=" << whp_lazy_emulator::to_hex(trap.guest_physical_address)
                      << " gva=" << whp_lazy_emulator::to_hex(trap.guest_virtual_address) << " source="
                      << whp_lazy_emulator::to_hex(trap.guest_virtual_address_valid ? trap.guest_virtual_address
                                                                                    : trap.guest_physical_address)
                      << "\n";

            if (page_base == read_page_base && trap.access_kind == whp_lazy_emulator::trap_access_kind::read)
            {
                whp_lazy_emulator::trap_response response = {};
                response.resolution = whp_lazy_emulator::trap_resolution::map_page;
                response.access = whp_lazy_emulator::map_access::read;
                response.host_page = read_page.data();
                response.message = "Mapped read-only data page from host memory.";
                return response;
            }

            if (page_base == write_page_base && trap.access_kind == whp_lazy_emulator::trap_access_kind::write)
            {
                whp_lazy_emulator::trap_response response = {};
                response.resolution = whp_lazy_emulator::trap_resolution::map_page;
                response.access = whp_lazy_emulator::map_access::read | whp_lazy_emulator::map_access::write;
                response.host_page = write_page.data();
                response.message = "Mapped writable data page from host memory.";
                return response;
            }

            if (page_base == tail_code_page_base && trap.access_kind == whp_lazy_emulator::trap_access_kind::execute)
            {
                if (stop_on_tail_execute)
                {
                    whp_lazy_emulator::trap_response response = {};
                    response.resolution = whp_lazy_emulator::trap_resolution::stop_emulation;
                    response.message = "Stopped on execute trap for tail code page.";
                    return response;
                }

                whp_lazy_emulator::trap_response response = {};
                response.resolution = whp_lazy_emulator::trap_resolution::map_page;
                response.access = whp_lazy_emulator::map_access::read | whp_lazy_emulator::map_access::execute;
                response.host_page = tail_code_page.data();
                response.message = "Mapped tail code page and resumed execution.";
                return response;
            }

            whp_lazy_emulator::trap_response response = {};
            response.resolution = whp_lazy_emulator::trap_resolution::stop_emulation;
            response.message = "Unhandled page trap at " + whp_lazy_emulator::to_hex(page_base);
            return response;
        }

        bool stop_on_tail_execute = false;
        const std::uint32_t read_page_target = static_cast<std::uint32_t>(read_page_base);
        const std::uint32_t write_page_target = static_cast<std::uint32_t>(write_page_base);
    };

    bool has_flag(int argc, char** argv, const std::string& flag)
    {
        for (int index = 1; index < argc; ++index)
        {
            if (argv[index] == flag)
            {
                return true;
            }
        }

        return false;
    }
} // namespace

int main(int argc, char** argv)
{
    try
    {
        const bool stop_on_tail_execute = has_flag(argc, argv, "--stop-on-tail-execute");

        std::cout << "Starting lazy WHP emulator demo\n";
        if (stop_on_tail_execute)
        {
            std::cout << "Tail execute trap will stop emulation instead of mapping the page.\n";
        }

        sample_memory sample(stop_on_tail_execute);
        whp_lazy_emulator::emulator emulator([&sample](const whp_lazy_emulator::trap_info& trap) { return sample.on_trap(trap); });

        emulator.map_memory({
            .host_address = sample.code_page.data(),
            .size = whp_lazy_emulator::page_size,
            .access = whp_lazy_emulator::map_access::read | whp_lazy_emulator::map_access::execute,
            .guest_address = code_page_base,
        });

        whp_lazy_emulator::cpu_state initial_state = {};
        initial_state.rip = code_page_base;
        initial_state.rsp = 0x9000;

        emulator.set_cpu_state(initial_state);
        emulator.run();

        const auto registers = emulator.read_registers();
        const auto write_value = *reinterpret_cast<const std::uint32_t*>(sample.write_page.data());

        std::cout << "Final registers\n";
        std::cout << "  RIP: " << whp_lazy_emulator::to_hex(registers.rip) << "\n";
        std::cout << "  RAX: " << whp_lazy_emulator::to_hex(registers.rax) << "\n";
        std::cout << "  RBX: " << whp_lazy_emulator::to_hex(registers.rbx) << "\n";
        std::cout << "  RCX: " << whp_lazy_emulator::to_hex(registers.rcx) << "\n";
        std::cout << "  RDX: " << whp_lazy_emulator::to_hex(registers.rdx) << "\n";
        std::cout << "  RSP: " << whp_lazy_emulator::to_hex(registers.rsp) << "\n";
        std::cout << "Host-backed write page value: " << whp_lazy_emulator::to_hex(write_value) << "\n";

        return 0;
    }
    catch (const std::exception& exception)
    {
        std::cerr << "Error: " << exception.what() << "\n";
        return 1;
    }
}
