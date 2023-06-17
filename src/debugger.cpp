#include "debugger.hpp"

class ptrace_expr_context : public dwarf::expr_context
{
    public:
    ptrace_expr_context (pid_t pid) : m_pid{pid} {};

    // dwarf::taddr reg(unsigned regnum) override;

    // dwarf::taddr pc() override;

    // dwarf::taddr deref_size (dwarf::taddr address, unsigned size) override;

    // dwarf::taddr xderef_size(dwarf::taddr address, dwarf::taddr asid, unsigned size) {};

    // dwarf::taddr form_tls_address(dwarf::taddr address) { };
    
    dwarf::taddr reg(unsigned regnum) override
    {
        return get_register_value_from_dwarf_register(m_pid, regnum);
    }

    dwarf::taddr pc() override
    {
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, m_pid, nullptr, &regs);
        return regs.rip;
    }

    dwarf::taddr deref_size(dwarf::taddr address, unsigned size) override
    {
        return ptrace(PTRACE_PEEKDATA, m_pid, address, nullptr);
    }

    private:
    pid_t m_pid;
};


debugger::debugger(std::string prog_name, pid_t pid) : m_prog_name{std::move(prog_name)}, m_pid{pid} 
{
    auto fd = open(m_prog_name.c_str(), O_RDONLY);

    m_elf = elf::elf{elf::create_mmap_loader(fd)};
    m_dwarf = dwarf::dwarf{dwarf::elf::create_loader(m_elf)};
    
};

void debugger::run()
{

    wait_for_signal();
    initialise_load_address();
    // int wait_status;
    // auto options = 0;

    // waitpid(m_pid, &wait_status, options);

    char *line = nullptr;

    while((line = linenoise("debugger> ")) != nullptr)
    {
        handle_command(line);
        linenoiseHistoryAdd(line);
        linenoiseFree(line);
    }
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

void debugger::handle_command(const std::string &line)
{
    auto args = split(line, ' ');
    auto command = args[0];

    if(is_prefix(command, "continue"))
        continue_execution();
    else if (is_prefix(command, "break")) 
    {
        if(args[1][0] == '0' && args[1][1] == 'x')
        {
            std::string addr {args[1], 2}; // assuming the second argument is the address 0xADDRESS
            auto address = std::stol(addr, 0, 16);
            set_breakpoint_at_address(address);
        }
        else if(args[1].find(':') != std::string::npos)
        {
            auto file_and_line = split(args[1], ':');
            set_breakpoint_at_source_line(file_and_line[0], std::stoi(file_and_line[1]));
        }
        else
        {
            set_breakpoint_at_function(args[1]);
        }

        
    }
    else if(is_prefix(command, "register"))
    {
        if(is_prefix(args[1], "dump"))
        {
            dump_registers();
        }
        else if(is_prefix(args[1], "read"))
        {
            std::cout << get_register_value(m_pid, get_register_from_name(args[2])) << std::endl;
        }
        else if(is_prefix(args[1], "write"))
        {
            std::string val {args[3], 2}; //assume  0xVAL
            set_register_value(m_pid, get_register_from_name(args[2]), std::stol(val, 0, 16)); 
        }
    }
    else if(is_prefix(command, "memory"))
    {
        std::string addr {args[2], 2}; // assume 0xADDRESS

        if(is_prefix(args[1], "read"))
        {
            std::cout << std::hex << read_memory(std::stol(addr, 0, 16)) << std::endl;
        }
        if(is_prefix(args[1], "write"))
        {
            std::string val {args[3], 2}; // assume 0xVAL
            write_memory(std::stol(addr, 0, 16), std::stol(val, 0, 16));
        }
    }
    else if(is_prefix(command, "step"))
    {
        step_in();
    }
    else if(is_prefix(command, "stepi"))
    {
        single_step_instruction_with_breakpoint_check();
        auto line_entry = get_line_entry_from_pc(get_pc());
        print_source(line_entry->file->path, line_entry->line);
    }
    else if(is_prefix(command, "next"))
    {
        step_over();
    }
    else if(is_prefix(command, "finish"))
    {
        step_out();
    }
    else if(is_prefix(command, "symbol"))
    {
        auto syms = lookup_symbol(args[1]);

        for(auto &&s : syms)
        {
            std::cout << s.name << " " << to_string(s.type) << " 0x" << std::hex << s.addr << std::endl;
        }
    }
    else if(is_prefix(command, "backtrace"))
    {
        print_backtrace();
    }
    else if(is_prefix(command, "variables"))
    {
        read_variables();
    }
    else
        std::cerr << "Unknown command" << std::endl;
}

void debugger::continue_execution()
{
    step_over_breakpoint();
    ptrace(PTRACE_CONT, m_pid, nullptr, nullptr);
    wait_for_signal();
}

void debugger::set_breakpoint_at_address(std::intptr_t address)
{
    std::cout << "Breakpoint set at address 0x" << std::hex << address << std::endl;
    breakpoint bp {m_pid, address};
    bp.enable();
    m_breakpoint[address] = bp;
}

void debugger::dump_registers()
{
    for(const auto &rd : g_register_descriptors)
    {
        std::cout << rd.name << " 0x" << std::setfill('0') << std::setw(16) << std::hex << get_register_value(m_pid, rd.r) << std::endl;
    }
}

uint64_t debugger::read_memory(uint64_t address)
{
    return ptrace(PTRACE_PEEKDATA, m_pid, address, nullptr);
}

void debugger::write_memory(uint64_t address, uint64_t value)
{
    ptrace(PTRACE_POKEDATA, m_pid, address, value);
}

uint64_t debugger::get_pc()
{
    return get_register_value(m_pid, reg::rip);
}

void debugger::set_pc(uint64_t pc)
{
    set_register_value(m_pid, reg::rip, pc);
}

void debugger::step_over_breakpoint()
{

    if(m_breakpoint.count(get_pc()))
    {
        auto &bp = m_breakpoint[get_pc()];

        if(bp.is_enabled())
        {
            bp.disable();
            ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr);
            wait_for_signal();
            bp.enable();
        }
    }
}

void debugger::wait_for_signal()
{
    int wait_status;
    auto options = 0;
    waitpid(m_pid, &wait_status, options);

    auto siginfo = get_signal_info();

    switch(siginfo.si_signo)
    {
        case SIGTRAP:
            handle_sigtrap(siginfo);
            break;
        case SIGSEGV:
            std::cout << "Segfault: " << siginfo.si_code << std::endl;
            break;
        default:
            std::cout << "Got signal " << strsignal(siginfo.si_signo) << std::endl;
    }
}

dwarf::die debugger::get_function_from_pc(uint64_t pc)
{

    for(auto &cu : m_dwarf.compilation_units())
    {

        if(die_pc_range(cu.root()).contains(pc))
        {
            for(const auto& die : cu.root())
            {
                if(die.tag == dwarf::DW_TAG::subprogram)
                {
                    if(die_pc_range(die).contains(pc))
                    {
                        return die;
                    }
                }
            }
        }

    }

    throw std::out_of_range{"Cannot find function"};
}

dwarf::line_table::iterator debugger::get_line_entry_from_pc(uint64_t pc)
{
    for(auto &cu : m_dwarf.compilation_units())
    {
        if(die_pc_range(cu.root()).contains(pc))
        {
            auto &lt = cu.get_line_table();

            auto it = lt.find_address(pc);

            if(it == lt.end())
            {
                throw std::out_of_range{"Cannot find line entry"};
            }
            else
            {
                return it;
            }
        }
    }
    
    throw std::out_of_range{"Cannot find line entry"};

}

void debugger::initialise_load_address()
{
    // use this if its a dynamic library
    if(m_elf.get_hdr().type == elf::et::dyn)
    {
        std::ifstream map("/proc/" + std::to_string(m_pid) + "/maps");

        std::string addr;
        std::getline(map, addr, '-');

        m_load_address = std::stol(addr, 0, 16);
    }

}

uint64_t debugger::offset_load_address(uint64_t addr)
{
    return addr - m_load_address;
}

void debugger::print_source(const std::string &file_name, unsigned line, unsigned n_lines_context)
{
    std::ifstream file {file_name};

    auto start_line = line <= n_lines_context ? 1 : line - n_lines_context;
    auto end_line = line + n_lines_context + (line < n_lines_context ? n_lines_context - line: 0) + 1;

    char c{};
    auto current_line = 1u;

    // skip lines up until start line
    while(current_line != start_line && file.get(c))
    {
        if(c == '\n')
        {
            ++current_line;
        }
    }

    // print when we are at current_line
    std::cout << (current_line == line ? "> ": " ");

    // print lines up until we reach end_line
    while(current_line <= end_line && file.get(c))
    {
        std::cout << c;
        if(c == '\n')
        {
            ++current_line;
            std::cout << (current_line == line ? "> " : " ");
        }
    }
}

siginfo_t debugger::get_signal_info()
{
    siginfo_t info;

    ptrace(PTRACE_GETSIGINFO, m_pid, nullptr, &info);

    return info;
}

void debugger::handle_sigtrap(siginfo_t info)
{
    switch(info.si_code )
    {
        // SI_KERNEL and TRAP_BRKPT is sent when a breakpoint is hit
        case SI_KERNEL:
        case TRAP_BRKPT:
        {
            // put program counter back since it passes the breakpoint
            set_pc(get_pc() - 1);
            std::cout << "Hit breakpoint at address 0x" << std::hex << get_pc() << std::endl;
            auto offset_pc = offset_load_address(get_pc()); // store offset of the pc for querying DWARF
            auto line_entry = get_line_entry_from_pc(offset_pc);
            print_source(line_entry->file->path, line_entry->line);
            return;
        }

        // For single stepping
        case TRAP_TRACE:
            return;
        default:
            std::cout << "SIGTRAP Code - Unknown " << info.si_code << std::endl;
            return;

    }
}

void debugger::single_step_instruction()
{
    ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr);
    wait_for_signal();
}

void debugger::single_step_instruction_with_breakpoint_check()
{
    if(m_breakpoint.count(get_pc()))
    {
        step_over_breakpoint();
    }
    else
    {
        single_step_instruction();
    }
}

void debugger::step_out()
{
    auto frame_pointer = get_register_value(m_pid, reg::rbp);
    auto return_address = read_memory(frame_pointer + 8);

    bool should_remove_breakpoint = false;

    if(!m_breakpoint.count(return_address))
    {
        set_breakpoint_at_address(return_address);
        should_remove_breakpoint = true;
    }

    continue_execution();

    if(should_remove_breakpoint)
    {
        remove_breakpoint(return_address);
    }
}

void debugger::remove_breakpoint(std::intptr_t addr)
{
    if(m_breakpoint.at(addr).is_enabled())
    {
        m_breakpoint.at(addr).disable();
    }
    m_breakpoint.erase(addr);
}

uint64_t debugger::get_offset_pc()
{
    return offset_load_address(get_pc());
}

void debugger::step_in()
{
    auto line = get_line_entry_from_pc(get_offset_pc())->line;

    while(get_line_entry_from_pc(get_offset_pc())->line == line)
    {
        single_step_instruction_with_breakpoint_check();
    }

    auto line_entry = get_line_entry_from_pc(get_offset_pc());

    print_source(line_entry->file->path, line_entry->line);
}


uint64_t debugger::offset_dwarf_address(uint64_t addr)
{
    return addr + m_load_address;
}

void debugger::step_over()
{
    auto func = get_function_from_pc(get_offset_pc());
    auto func_entry = at_low_pc(func);
    auto func_end = at_high_pc(func);

    auto line = get_line_entry_from_pc(func_entry);
    auto start_line = get_line_entry_from_pc(get_offset_pc());

    // We must ensure that all break points are properly tracked within step functions 
    // and to achieve this, we will use a std::vector to maintain a record of them.
    // To establish all break points, we iterate through the table entries 
    // until we encounter a value that falls outside the function's range. 
    // For each entry, we verify that it is not the current line 
    // and that no breakpoint has already been set at that particular location. 
    // Additionally, we need to adjust the addresses obtained from the DWARF information
    //  by the load address in order to accurately set breakpoints.
    std::vector<std::intptr_t> to_delete{};

    while(line->address < func_end)
    {
        auto load_address = offset_dwarf_address(line->address);
        if(line->address != start_line->address && !m_breakpoint.count(load_address))
        {
            set_breakpoint_at_address(load_address);
            to_delete.push_back(load_address);
        }
        ++line;
    }

    auto frame_pointer = get_register_value(m_pid, reg::rbp);
    auto return_address = read_memory(frame_pointer = 8);
    if(!m_breakpoint.count(return_address))
    {
        set_breakpoint_at_address(return_address);
        to_delete.push_back(return_address);
    }

    continue_execution();

    for(auto addr : to_delete)
    {
        remove_breakpoint(addr);
    }
}

void debugger::set_breakpoint_at_function(const std::string &name)
{
    for(const auto &cu : m_dwarf.compilation_units())
    {
        for(const auto &die : cu.root())
        {
            if(die.has(dwarf::DW_AT::name) && at_name(die) == name)
            {
                auto low_pc = at_low_pc(die);
                auto entry = get_line_entry_from_pc(low_pc);
                ++entry;
                set_breakpoint_at_address(offset_dwarf_address(entry->address));
            }
        }
    }
}

bool is_suffix(const std::string &s, const std::string &of)
{
    if(s.size() > of.size()) return false;

    auto diff = of.size() - s.size();
    return std::equal(s.begin(), s.end(), of.begin() + diff);
}

void debugger::set_breakpoint_at_source_line(const std::string &file, unsigned line)
{
    for(const auto &cu : m_dwarf.compilation_units())
    {
        if(is_suffix(file, at_name(cu.root())))
        {
            const auto &lt = cu.get_line_table();

            for(const auto &entry : lt)
            {
                if(entry.is_stmt && entry.line == line)
                {
                    set_breakpoint_at_address(offset_dwarf_address(entry.address));
                    return;
                }
            }
        }
    }
}

std::vector<symbol> debugger::lookup_symbol (const std::string &name)
{
    std::vector<symbol> syms;

    for(auto &sec : m_elf.sections())
    {
        if(sec.get_hdr().type  != elf::sht::symtab && sec.get_hdr().type != elf::sht::dynsym)
            continue;

        for(auto sym: sec.as_symtab())
        {
            if(sym.get_name() == name)
            {
                auto &d = sym.get_data();
                syms.push_back(symbol{to_symbol_type(d.type()), sym.get_name(), d.value});
            }
        }

        return syms;
    }
}

void debugger::print_backtrace()
{
    auto output_frame = [frame_number = 0] (auto&& func) mutable {
        std::cout << "frame " << frame_number++ << ": 0x" << dwarf::at_low_pc(func) 
                  << " " << dwarf::at_name(func) << std::endl;
    };

    auto current_func = get_function_from_pc(offset_load_address(get_pc()));
    output_frame(current_func);

    auto frame_pointer = get_register_value(m_pid, reg::rbp);
    auto return_address = read_memory(frame_pointer + 8);

    while(dwarf::at_name(current_func) != "main")
    {
        current_func = get_function_from_pc (offset_load_address(return_address));

        output_frame(current_func);
        frame_pointer = read_memory(frame_pointer);
        return_address = read_memory(frame_pointer + 8);
    }

}
void debugger::read_variables()
{
    using namespace dwarf;

    // find the function we are currently in
    auto func = get_function_from_pc(get_offset_pc());

    // loop through the function and look at DW_AT_location
    for(const auto & die : func) 
    {
        if(die.tag == DW_TAG::variable)
        {
            auto loc_val = die[DW_AT::location];

            if(loc_val.get_type() == value::type::exprloc)
            {
                ptrace_expr_context context {m_pid};
                auto result = loc_val.as_exprloc().evaluate(&context);

                switch(result.location_type)
                {
                    case expr_result::type::address:
                    {
                        auto value = read_memory(result.value);
                        std::cout << at_name(die) << " (0x" << std::hex << result.value << ") = " << value << std::endl;
                        break;
                    }

                    case expr_result::type::reg:
                    {
                        std::cout << "Result Value: " << result.value << std::endl;
                        auto value = get_register_value_from_dwarf_register(m_pid, result.value);
                        std::cout << at_name(die) << " (reg " << result.value << ") = " << value << std::endl;
                        break;
                    }
                    
                    default:
                    throw std::runtime_error{"Unhandled variable location"};
                }
            }
        }
    }
}