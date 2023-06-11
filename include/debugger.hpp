#pragma once

#include <string>
#include <sys/types.h>
#include <sys/wait.h>
#include <linenoise.h>
#include <iostream>
#include <vector>
#include <sstream>
#include <sys/ptrace.h>

class debugger
{
    public: debugger(std::string prog_name, pid_t pid);
    void run();

    private:
    std::string m_prog_name;
    pid_t m_pid;

    private:
    void handle_command(const std::string &line);
    void continue_execution();
};