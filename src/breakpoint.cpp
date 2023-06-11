#include "breakpoint.hpp"

void breakpoint::enable()
{
    // changing code to have a in3 instruction on the fly

    // get data for the pid
    // returns 64 bits that are at the address used by the process
    auto data = ptrace(PTRACE_PEEKDATA, m_pid, m_addr, nullptr);
    m_saved_data = static_cast<uint8_t>(data & 0xff) // save bottom byte of the data
    uint64_t int3 = 0xcc; // int 3 instruction encoded as 0xcc
    // (data & ~0xff) -> zeroes out bototm  byte of the data and replaced with int3 (0xcc)
    uint64_t data_with_int3 = ((data &~0xff) | int3); // bottom byte = 0xcc

    ptrace(PTRACE_POKEDATA, m_pid, m_addr, data_with_int3);

    m_enabled = true;
}