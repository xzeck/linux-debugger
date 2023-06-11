#include <iostream>
#include<unistd.h>
#include <sys/ptrace.h>
#include <sys/personality.h>
#include "debugger.hpp"
#include "linenoise.h"


void execute_debugee(const std::string &prog_name)
{
    if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0)
    {
        std::cerr << "Error in ptrace" << std::endl;
        return;
    }

    execl(prog_name.c_str(), prog_name.c_str(), nullptr);

}

int main(int argc, char * argv[])
{
    if(argc < 2)
    {
        std::cerr << "Program name not specified";
        return -1;
    }


    auto prog = argv[1];

    auto pid = fork();

    if(pid == 0)
    {
        // child process

        // turn off address space layout randomization
        // this is to make it easier to test as we are dealing 
        // with addresses of the functions rather than function names
        personality(ADDR_NO_RANDOMIZE);
        execute_debugee(prog);
    }
    else if (pid >= 1)
    {
        // parent process
        std::cout << "Started debugging" << pid << "\n";
        debugger dbg{prog, pid};
        dbg.run();
    }

}