#include "registers.hpp"
#include <sys/user.h>
#include <sys/ptrace.h>
#include <algorithm>

uint64_t get_register_value(pid_t pid, reg r)
{
    user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, nullptr, &regs);

    auto it = std::find_if(begin(g_register_descriptors), end(g_register_descriptors), 
                        [r](auto&& rd) { return rd.r == r; });

    return *(reinterpret_cast<uint64_t*>(&regs) + (it - begin(g_register_descriptors)));
}

void set_register_value(pid_t pid , reg r, uint64_t value)
{
    user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, nullptr, &regs);
    auto it = std::find_if(begin(g_register_descriptors), end(g_register_descriptors),
                           [r](auto && rd) { return rd.r == r; });

    *(reinterpret_cast<uint64_t*>(&regs) +  (it - begin(g_register_descriptors))) = value;

    ptrace(PTRACE_SETREGS, pid, nullptr, &regs);
}