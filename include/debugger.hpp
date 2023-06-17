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
#include <iostream>

#include "breakpoint.hpp"
#include "registers.hpp"
#include "dwarf/dwarf++.hh"
#include "elf/elf++.hh"
#include "symbol.hpp"
#include "expr_context.hpp"

class debugger
{
    public: 
    debugger(std::string prog_name, pid_t pid);
    void run();
    void set_breakpoint_at_address(std::intptr_t address);
    void print_source(const std::string &file_name, unsigned line, unsigned n_lines_context=2);

    private:
    std::string m_prog_name;
    pid_t m_pid;
    uint64_t m_load_address = 0;
    dwarf::dwarf m_dwarf;
    elf::elf m_elf;

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
    dwarf::die get_function_from_pc(uint64_t pc);
    dwarf::line_table::iterator get_line_entry_from_pc(uint64_t pc);
    void initialise_load_address();
    uint64_t offset_load_address(uint64_t addr);
    siginfo_t get_signal_info();
    void handle_sigtrap(siginfo_t info);
    void single_step_instruction();
    void single_step_instruction_with_breakpoint_check();
    void step_out();
    void remove_breakpoint(std::intptr_t addr);
    void step_in();
    uint64_t get_offset_pc();
    uint64_t offset_dwarf_address(uint64_t addr);
    void step_over();
    void set_breakpoint_at_function(const std::string &name);
    void set_breakpoint_at_source_line(const std::string &file, unsigned line);
    std::vector<symbol> lookup_symbol(const std::string &name);
    void print_backtrace();
    void read_variables();
};