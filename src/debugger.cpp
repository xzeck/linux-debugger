#include "debugger.hpp"

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
        std::string addr {args[1], 0}; // assuming the second argument is the address
        std::cout << addr << std::endl;
        auto address = std::stol(addr, 0, 16);

        
        set_breakpoint_at_address(address);
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