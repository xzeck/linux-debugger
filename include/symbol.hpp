#pragma once

#include <string>
#include <cstdint>
#include "elf/elf++.hh"

enum class symbol_type
{
    notype,
    object, 
    func,
    section, 
    file,
};

struct symbol
{
    symbol_type type;
    std::string name;
    std::uintptr_t addr;
};

std::string to_string(symbol_type st);

symbol_type to_symbol_type(elf::stt sym);