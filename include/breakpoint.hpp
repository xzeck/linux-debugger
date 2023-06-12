#pragma once

#include <string>
#include <sys/types.h>
#include <sys/wait.h>
#include <linenoise.h>
#include <iostream>
#include <vector>
#include <sstream>
#include <sys/ptrace.h>
#include <cstdint>


class breakpoint
{
    public:
    breakpoint() = default;
    breakpoint(pid_t pid, std::intptr_t addr) 
        : m_pid{pid}, m_addr{addr}, m_enabled{false}, m_saved_data{} 
    {}
    
    void enable();
    void disable();

    auto is_enabled() const -> bool {return m_enabled; }
    auto get_address() const -> std::intptr_t { return m_addr; }

    void set_break_point_at_address(std::intptr_t addr);

    private: 
    pid_t m_pid;
    std::intptr_t m_addr;
    bool m_enabled;
    uint8_t m_saved_data; // used to be at the breakpoint address

};