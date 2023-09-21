#ifndef __TikiBreak_H_

#include<iostream>
#include<unistd.h>
#include<sys/types.h>
#include<sys/ptrace.h>
#include <sys/wait.h>

#define __TikiBreak_H_
#define int3_byte 0xcc



class Tikibreakpoint{
    public:
        Tikibreakpoint(pid_t pid,std::intptr_t addr):b_pid{pid},b_addr{addr},enabled{true},save_byte{0}{};
        Tikibreakpoint():b_pid{0},b_addr{0},enabled{true},save_byte{0}{};
        void enable();
        void disable();

        auto is_enabled() const -> bool { return enabled;}
        auto get_addr() const -> std::intptr_t{return b_addr;}



    private:
        pid_t b_pid;
        std::intptr_t b_addr;
        bool enabled;
        uint8_t save_byte;
};



#endif 