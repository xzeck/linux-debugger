#pragma once

#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <linenoise.h>
#include <iostream>
#include <vector>
#include <sstream>
#include <sys/ptrace.h>
#include <unordered_map>
#include <cstdint>
#include "breakpoint.hpp"

class debugger
{
    public: debugger(std::string prog_name, pid_t pid);
    void run();
    void set_breakpoint_at_address(std::intptr_t address);

    private:
    std::string m_prog_name;
    pid_t m_pid;

    private:
    void handle_command(const std::string &line);
    void continue_execution();
    std::unordered_map<std::intptr_t, breakpoint> m_breakpoint;
    void dump_registers();
    uint64_t read_memory(uint64_t address);
    void write_memory(uint64_t address, uint64_t value);
    uint64_t get_pc();
    void set_pic(uint64_t pc);
};