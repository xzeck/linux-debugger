#pragma once
 
#include "dwarf/dwarf++.hh"
#include "registers.hpp"
#include <sys/types.h>
#include <sys/user.h>


// class ptrace_expr_context : public dwarf::expr_context
// {
//     public:
//     ptrace_expr_context (pid_t pid) : m_pid{pid} {};

//     // dwarf::taddr reg(unsigned regnum) override;

//     // dwarf::taddr pc() override;

//     // dwarf::taddr deref_size (dwarf::taddr address, unsigned size) override;

//     // dwarf::taddr xderef_size(dwarf::taddr address, dwarf::taddr asid, unsigned size) {};

//     // dwarf::taddr form_tls_address(dwarf::taddr address) { };
    
//     dwarf::taddr ptrace_expr_context::reg(unsigned regnum) override
//     {
//         return get_register_value_from_dwarf_register(m_pid, regnum);
//     }

//     dwarf::taddr ptrace_expr_context::pc() override
//     {
//         struct user_regs_struct regs;
//         ptrace(PTRACE_GETREGS, m_pid, nullptr, &regs);
//         return regs.rip;
//     }

//     dwarf::taddr ptrace_expr_context::deref_size(dwarf::taddr address, unsigned size) override
//     {
//         return ptrace(PTRACE_PEEKDATA, m_pid, address, nullptr);
//     }

//     private:
//     pid_t m_pid;
// };