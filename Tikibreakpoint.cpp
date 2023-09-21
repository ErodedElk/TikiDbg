#include"Tikibreakpoint.h"

void Tikibreakpoint::enable(){
    auto data = ptrace(PTRACE_PEEKDATA, b_pid,b_addr, nullptr);
    save_byte=static_cast<uint8_t>(data&0xff);
    uint64_t data_with_int3 = ((data & ~0xff) | int3_byte); //set bottom byte to 0xcc
    ptrace(PTRACE_POKEDATA, b_pid, b_addr, data_with_int3);

    enabled = true;
}

void Tikibreakpoint::disable(){
    auto data = ptrace(PTRACE_PEEKDATA, b_pid,b_addr, nullptr);
    uint64_t data_with_int3 = ((data & ~0xff) | save_byte); //set bottom byte to 0xcc
    ptrace(PTRACE_POKEDATA, b_pid, b_addr, data_with_int3);
    enabled = false;
}