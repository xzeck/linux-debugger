#include "expr_context.hpp"

dwarf::taddr ptrace_expr_context::reg(unsigned regnum) override
{
    return get_register_value_from_dwarf_register(m_pid, regnum);
}

dwarf::taddr ptrace_expr_context::pc() override
{
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, m_pid, nullptr, &regs);
    return regs.rip;
}

dwarf::taddr ptrace_expr_context::deref_size(dwarf::taddr address, unsigned size) override
{
    return ptrace(PTRACE_PEEKDATA, m_pid, address, nullptr);
}

