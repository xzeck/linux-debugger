#include "debugger.hpp"

debugger::debugger(std::string prog_name, pid_t pid) : m_prog_name{std::move(prog_name)}, m_pid{pid} {};

void debugger::run()
{
    int wait_status;
    auto options = 0;

    waitpid(m_pid, &wait_status, options);

    char *line = nullptr;

    while((line = linenoise("minidbg> ")) != nullptr)
    {
        handle_command(line);
        linenoiseHistoryAdd(line);
        linenoiseFree(line);
    }
}

void debugger::handle_command(const std::string &line)
{
    auto args = split(line, ' ');
    auto command = args[0];

    if(is_prefix(command, "continue"))
        continue_execution();
    else
        std::cerr << "Unknown command" << std::endl;
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

void debugger::continue_execution()
{
    ptrace(PTRACE_CONT, m_pid, nullptr, nullptr);

    int wait_status;
    auto options = 0;
    waitpid (m_pid, &wait_status, options);
}