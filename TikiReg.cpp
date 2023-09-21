#include"TikiReg.h"

uint64_t get_register_value(pid_t pid, reg r) {
    user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, nullptr, &regs);

    auto it = std::find_if(begin(g_register_descriptors), end(g_register_descriptors),[r](auto&& rd){return rd.r==r;});
    return *(reinterpret_cast<uint64_t*>(&regs)+(it-begin(g_register_descriptors)));
}


void set_register_value(pid_t pid,reg r,uint64_t value)
{
    user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, nullptr, &regs);

    auto it = std::find_if(begin(g_register_descriptors), end(g_register_descriptors),[r](auto&& rd){return rd.r==r;});
    *(reinterpret_cast<uint64_t*>(&regs)+(it-begin(g_register_descriptors)))=value;
    ptrace(PTRACE_SETREGS, pid, nullptr, &regs);
}

uint64_t get_register_value_from_register(pid_t pid, unsigned r)
{
    auto it = std::find_if(begin(g_register_descriptors), end(g_register_descriptors),
                           [r](auto&& rd) { return rd.dwarf_r == r; });
    if (it == end(g_register_descriptors)) {
        throw std::out_of_range{"Unknown dwarf register"};
    }
    return get_register_value(pid, it->r);
}

std::string get_register_name(reg r)
{
    auto it = std::find_if(begin(g_register_descriptors), end(g_register_descriptors),[r](auto&& rd){return rd.r==r;});
    if (it == end(g_register_descriptors)) {
        throw std::out_of_range{"Unknown register"};
    }
    return it->name;
}

reg get_register_by_name(const std::string& name)
{
    auto it = std::find_if(begin(g_register_descriptors), end(g_register_descriptors),
                           [name](auto&& rd) { return rd.name == name; });
    if (it == end(g_register_descriptors)) {
        throw std::out_of_range{"Unknown register"};
    }
    return it->r;
}
 

