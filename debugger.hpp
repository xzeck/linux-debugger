#include <string>
#include <sys/types.h>

class debugger
{
    public: debugger(std::string prog_name, pid_t pid);
    void run();

    private:
    std::string m_prog_name;
    pid_t m_pid;
};