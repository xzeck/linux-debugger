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
#include <fstream>
#include <utility>
#include <iomanip>
#include <fcntl.h>

#include "breakpoint.hpp"
#include "registers.hpp"
#include "dwarf/dwarf++.hh"
#include "elf/elf++.hh"


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
    void set_pc(uint64_t pc);
    void step_over_breakpoint();
    void wait_for_signal();
    dwarf::dwarf m_dwarf;
    elf::elf m_elf;
    dwarf::die get_functions_from_pc(uint64_t pc);
};