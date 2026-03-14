#pragma once

#include <Windows.h>

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace whp_lazy_emulator
{
constexpr std::uint64_t page_size = 0x1000;

enum class trap_access_kind
{
    read,
    write,
    execute,
};

enum class trap_resolution
{
    map_page,
    stop_emulation,
    deny_access,
};

enum class map_access : std::uint32_t
{
    none = 0,
    read = 1u << 0,
    write = 1u << 1,
    execute = 1u << 2,
};

struct cpu_state
{
    std::uint64_t rip = 0;
    std::uint64_t rsp = 0;
    std::uint64_t rflags = 0x2;
    std::uint64_t rax = 0;
    std::uint64_t rbx = 0;
    std::uint64_t rcx = 0;
    std::uint64_t rdx = 0;
    std::uint64_t rsi = 0;
    std::uint64_t rdi = 0;
    std::uint64_t rbp = 0;
};

struct trap_info
{
    trap_access_kind access_kind = trap_access_kind::read;
    std::uint64_t guest_physical_address = 0;
    std::uint64_t guest_virtual_address = 0;
    bool guest_virtual_address_valid = false;
    std::vector<std::uint8_t> instruction_bytes;
};

struct trap_response
{
    trap_resolution resolution = trap_resolution::deny_access;
    map_access access = map_access::none;
    void* host_page = nullptr;
    std::vector<std::uint8_t> page_bytes;
    std::string message;
};

struct mapped_range
{
    void* host_address = nullptr;
    std::size_t size = 0;
    map_access access = map_access::none;
    std::optional<std::uint64_t> guest_address;
};

struct register_snapshot
{
    std::uint64_t rip = 0;
    std::uint64_t rax = 0;
    std::uint64_t rbx = 0;
    std::uint64_t rcx = 0;
    std::uint64_t rdx = 0;
    std::uint64_t rsp = 0;
};

class emulator
{
public:
    using trap_handler = std::function<trap_response(const trap_info&)>;

    explicit emulator(trap_handler trap_handler_callback);
    ~emulator();

    emulator(const emulator&) = delete;
    emulator& operator=(const emulator&) = delete;

    emulator(emulator&&) noexcept;
    emulator& operator=(emulator&&) noexcept;

    void set_cpu_state(const cpu_state& state);
    void map_memory(const mapped_range& range);
    void run();
    register_snapshot read_registers() const;

private:
    class implementation;
    std::unique_ptr<implementation> implementation_;
};

std::uint64_t align_down_to_page(std::uint64_t value);
bool is_page_aligned(std::uint64_t value);
map_access operator|(map_access left, map_access right);
map_access operator&(map_access left, map_access right);
map_access& operator|=(map_access& left, map_access right);
std::string to_hex(std::uint64_t value);
} // namespace whp_lazy_emulator
