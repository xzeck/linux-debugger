#include "debugger.hpp"
#include "registers.hpp"
#include <iomanip>

debugger::debugger(std::string prog_name, pid_t pid) : m_prog_name{std::move(prog_name)}, m_pid{pid} {};

void debugger::run()
{
    int wait_status;
    auto options = 0;

    waitpid(m_pid, &wait_status, options);

    char *line = nullptr;

    while((line = linenoise("debugger> ")) != nullptr)
    {
        handle_command(line);
        linenoiseHistoryAdd(line);
        linenoiseFree(line);
    }
}

std::vector<std::string> split(const std::string &s, char delimiter)
{
    std::vector<std::string> out {};
    std::stringstream ss {s};
    std::string item;

    while(std::getline(ss, item, delimiter))
    {
        out.push_back(item);
    }

    return out;
}

bool is_prefix(const std::string &s, const std::string &of)
{
    if(s.size() > of.size()) return false;

    return std::equal(s.begin(), s.end(), of.begin());
}

void debugger::handle_command(const std::string &line)
{
    auto args = split(line, ' ');
    auto command = args[0];

    if(is_prefix(command, "continue"))
        continue_execution();
    else if (is_prefix(command, "break")) 
    {
        std::string addr {args[1], 2}; // assuming the second argument is the address 0xADDRESS
        std::cout << addr << std::endl;
        auto address = std::stol(addr, 0, 16);

        
        set_breakpoint_at_address(address);
    }
    else if(is_prefix(command, "register"))
    {
        if(is_prefix(args[1], "dump"))
        {
            dump_registers();
        }
    }
    else if(is_prefix(args[1], "read"))
    {
        std::cout << get_register_value(m_pid, get_register_from_name(args[2])) << std::endl;
    }
    else if(is_prefix(args[1], "write"))
    {
        std::string val {args[3], 2}; //assume  0xVAL
        set_register_value(m_pid, get_register_from_name(args[2]), std::stol(val, 0, 16)); 
    }
    else if(is_prefix(command, "memory"))
    {
        std::string addr {args[2], 2}; // assume 0xADDRESS

        if(is_prefix(args[1], "read"))
        {
            std::cout << std::hex << read_memory(std::stol(addr, 0, 16)) << std::endl;
        }
        if(is_prefix(args[1], "write"))
        {
            std::string val {args[3], 2}; // assume 0xVAL
            write_memory(std::stol(addr, 0, 16), std::stol(val, 0, 16));
        }
    }
    else
        std::cerr << "Unknown command" << std::endl;
}

void debugger::continue_execution()
{
    ptrace(PTRACE_CONT, m_pid, nullptr, nullptr);

    int wait_status;
    auto options = 0;
    waitpid (m_pid, &wait_status, options);
}

void debugger::set_breakpoint_at_address(std::intptr_t address)
{
    std::cout << "Breakpoint set at address 0x" << std::hex << address << std::endl;
    breakpoint bp {m_pid, address};
    bp.enable();
    m_breakpoint[address] = bp;
}

void debugger::dump_registers()
{
    for(const auto &rd : g_register_descriptors)
    {
        std::cout << rd.name << " 0x" << std::setfill('0') << std::setw(16) << std::hex << get_register_value(m_pid, rd.r) << std::endl;
    }
}

uint64_t debugger::read_memory(uint64_t address)
{
    return ptrace(PTRACE_PEEKDATA, m_pid, address, nullptr);
}

void debugger::write_memory(uint64_t address, uint64_t value)
{
    ptrace(PTRACE_POKEDATA, m_pid, address, value);
}