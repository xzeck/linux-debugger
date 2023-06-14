#include "debugger.hpp"


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
    int wait_status;
    auto options = 0;

    waitpid(m_pid, &wait_status, options);

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
        std::string addr {args[1], 2}; // assuming the second argument is the address 0xADDRESS
        std::cout << addr << std::endl;
        auto address = std::stol(addr, 0, 16);

        
        set_breakpoint_at_address(address);
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
    // The execution will be decremented by 1 as it goes beyond the breakpoint.
    auto possible_breakpoint_location = get_pc() - 1;

    if(m_breakpoint.count(possible_breakpoint_location))
    {
        auto &bp = m_breakpoint[possible_breakpoint_location];

        if(bp.is_enabled())
        {
            auto previous_instruction_address = possible_breakpoint_location;
            set_pc(previous_instruction_address);

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
}

dwarf::die debugger::get_functions_from_pc(uint64_t pc)
{
    for(auto &cu : m_dwarf.compilation_units())
    {
        if(die_pc_range(cu.root()).contains(pc)) 
        {
            for(const auto &die : cu.root())
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

