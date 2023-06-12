#include "registers.hpp"

uint64_t get_register_value(pid_t pid, reg r)
{
    user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, nullptr, &regs);

    auto it = std::find(begin(g_register_descriptors), end(g_register_descriptors), [r](auto&& rd) { return rd.r == r; });

    return *(reinterpret_cast<uint64_t*>(&args) + (it - begin(g_register_descriptors)));
}