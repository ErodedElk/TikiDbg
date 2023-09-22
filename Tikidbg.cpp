#include <sys/personality.h>
#include "Tikidbg.h"
#include"Tikibreakpoint.h"
#include <unordered_map>
#include"TikiReg.h"
#include <iomanip>
#include"libelfin/elf/elf++.hh"
#include"libelfin/dwarf/dwarf++.hh"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include<fstream>
#include<capstone/capstone.h>
#include <sys/uio.h>
class TikiDbg{
    public:
        TikiDbg(std::string program,pid_t pid): program_name{std::move(program)},pid_me{pid}{
            auto fd = open(program_name.c_str(),0);
            // create_mmap_loader: args is UNIX file descriptor
            // open is used  instead of std::ifstream
            //elf_me = elf::elf{elf::create_mmap_loader(fd)};
            //dwarf_me= dwarf::dwarf{dwarf::elf::create_loader(elf_me)};
        }

        void run();
        void handle_command(const std::string &line);
        void continue_execution();

        void set_breakpoint_at_addr(std::intptr_t addr);
        void delete_breakpoint_at_addr(std::intptr_t addr);
        void dump_registers();

        uint64_t read_memory(uint64_t addr);
        void write_memory(uint64_t addr,uint64_t value);

        uint64_t get_pc(){return get_register_value(pid_me,reg::rip);};
        void set_pc(uint64_t value){set_register_value(pid_me,reg::rip,value);};

        void step_over_breakpoint();
        void single_step_instruction_with_breakpoint_check();
        void wait_for_signal();

        // dwarf::die get_function_from_pc(uint64_t pc);
        // dwarf::line_table::iterator get_line_entry_from_pc(uint64_t pc);
        void initialise_load_address();
        uint64_t offset_load_address(uint64_t addr);
        void print_source(const std::string & fimename,unsigned line,unsigned n_lines_context);
        void print_disassembly(uint64_t addr,uint64_t size,size_t n_code);


        siginfo_t get_signal_info();
        void handle_sigtrap(siginfo_t info);

    private:
        std::string program_name;
        pid_t pid_me;
        std::unordered_map<std::intptr_t,Tikibreakpoint> t_breakpoints;

        dwarf::dwarf dwarf_me;
        elf::elf elf_me;
        uint64_t binary_addr_base;
        csh cs_handle;
};

void TikiDbg::single_step_instruction_with_breakpoint_check()
{
    if (t_breakpoints.count(get_pc()-1)) {

        //set_pc(get_pc()-1);
        step_over_breakpoint();
    }
    else {
        ptrace(PTRACE_SINGLESTEP, pid_me, nullptr, nullptr);
        wait_for_signal();
    }
}

void TikiDbg::print_disassembly(uint64_t addr,uint64_t size,size_t n_code)
{
    cs_insn *insn;
	size_t count;
    struct iovec local[1];
    struct iovec remote[1];
    
    uint8_t buf1[0x100];

    ssize_t nread;

    local[0].iov_base = buf1;
    local[0].iov_len = 0x100-1;

    remote[0].iov_base = reinterpret_cast<void*>(addr);
    remote[0].iov_len = size;
    nread = process_vm_readv(pid_me, local, 1, remote, 1, 0);

    if(t_breakpoints.count(addr))
    {
        auto & bp=t_breakpoints[addr];
        
        buf1[0]=bp.get_save_byte();
    }

    count = cs_disasm(cs_handle, buf1, 255, addr, n_code, &insn);
    if(count > 0)
    {
        std::cout << "----------------TikiDbg----------------" << std::endl ;
        for(int i=0; i<count; i++)
        {
            std::cout << "0x" << std::hex << insn[i].address << ":\t" << insn[i].mnemonic << "\t\t" << insn[i].op_str << std::endl;
        }
        cs_free(insn, count);
    }
    else{
        throw std::runtime_error("Disassembly failed");
    }
}


void TikiDbg::handle_sigtrap(siginfo_t info)
{
    switch (info.si_code) {
        //one of these will be set if a breakpoint was hit
        case SI_KERNEL:
        case TRAP_BRKPT:
        {
            // set_pc(get_pc()-1); //put the pc back where it should be
            std::cout << "Hit breakpoint at address 0x" << std::hex << get_pc()-1 << std::endl;
            // auto offset_pc = offset_load_address(get_pc()); //rember to offset the pc for querying DWARF
            // auto line_entry = get_line_entry_from_pc(offset_pc);
            uint64_t now_pc= get_pc()-1;
            print_disassembly(now_pc,0x50,7);
            return;
        }
        //this will be set if the signal was sent by single stepping
        case TRAP_TRACE:
        {
            uint64_t now_pc= get_pc();
            print_disassembly(now_pc,0x50,7);
            return;
        }

            
        default:
            std::cout << "Unknown SIGTRAP code " << info.si_code << std::endl;
            return;
    }
}

siginfo_t TikiDbg::get_signal_info()
{
    siginfo_t info;
    ptrace(PTRACE_GETSIGINFO,pid_me,nullptr,&info);
    return info;
}

void TikiDbg::print_source(const std::string & filename,unsigned line,unsigned n_lines_context)
{
    std::ifstream file{filename};
    auto start_line= line <= n_lines_context? 1: line-n_lines_context;
    auto end_line= line +n_lines_context + (line< n_lines_context? n_lines_context-line: 0)+1;
    char c{};
    auto current=1u;
    while(current != start_line && file.get(c))
    {
        if(c == '\n')
        {
            ++current;
        }
    }

    std::cout << (current == line? "> " : " ");
    while (current <=end_line && file.get(c))
    {
        std::cout << c;
        if(c == '\n')
        {
            ++current;
            std::cout << (current == line? "> " : " ");
        }
    }
    std::cout << std::endl;
}

uint64_t TikiDbg::offset_load_address(uint64_t addr)
{
    return addr- binary_addr_base;
}

void TikiDbg::initialise_load_address()
{
    std::ifstream map("/proc/"+ std::to_string(pid_me)+"/maps");
    std::string addr;
    std::getline(map, addr,'-');
    binary_addr_base = std::stoll(addr, 0, 16);
}

// dwarf::line_table::iterator TikiDbg::get_line_entry_from_pc(uint64_t pc)
// {
//     for(auto & cu : dwarf_me.compilation_units())
//     {
//         if(die_pc_range(cu.root()).contains(pc))
//         {
//             auto & lt= cu.get_line_table();
//             auto it =lt.find_address(pc);
//             if(it == lt.end())
//             {
//                 throw std::out_of_range{"Cannot find line"};
//             }
//             else{
//                 return it;
//             }
//         }
//     }
//     throw std::out_of_range{"Cannot find line"};
// }

// dwarf::die TikiDbg::get_function_from_pc(uint64_t pc)
// {
//     for(auto & cu:dwarf_me.compilation_units())
//     {
//         if(die_pc_range(cu.root()).contains(pc))
//         {
//             for(const auto & die:cu.root())
//             {
//                 if(die.tag == dwarf::DW_TAG::subprogram)
//                 {
//                     if(die_pc_range(die).contains(pc))
//                     {
//                         return die;
//                     }
//                 }
//             }
//         }
//     }
//     throw std::out_of_range{"Cannot find function"};
// }

void TikiDbg::wait_for_signal()
{
    int wait_status;
    auto options=0;
    waitpid(pid_me,&wait_status,options);


    auto siginfo = get_signal_info();
    switch (siginfo.si_signo) {
    case SIGTRAP:
        handle_sigtrap(siginfo);
        break;
    case SIGSEGV:
        std::cout << "segfault. Reason: " << siginfo.si_code << std::endl;
        break;
    default:
        std::cout << "Got signal " << strsignal(siginfo.si_signo) << std::endl;
    }

}

void TikiDbg::step_over_breakpoint()
{
    auto breakpoint_addr=get_pc()-1;
    if(t_breakpoints.count(breakpoint_addr))
    {
        auto & bp = t_breakpoints[breakpoint_addr];
        if(bp.is_enabled())
        {
            set_pc(breakpoint_addr);
            bp.disable();
            ptrace(PTRACE_SINGLESTEP,pid_me,nullptr,nullptr);
            wait_for_signal();
            bp.enable();
        }
    }
}

uint64_t TikiDbg::read_memory(uint64_t addr)
{
    //PTRACE_PEEKDATA:读取 2 byte
    //TODO: process_vm_readv will be used 
    uint64_t ret=0;
    ret|= ptrace(PTRACE_PEEKDATA,pid_me,addr,nullptr);
    ret|= (ptrace(PTRACE_PEEKDATA,pid_me,addr+2,nullptr)<<16);
    ret|= (ptrace(PTRACE_PEEKDATA,pid_me,addr+4,nullptr)<<32);
    ret|= (ptrace(PTRACE_PEEKDATA,pid_me,addr+6,nullptr)<<48);
    return ret;
}

void TikiDbg::write_memory(uint64_t addr, uint64_t value)
{
    //TODO: process_vm_writev will be used 
    ptrace(PTRACE_POKEDATA,pid_me,addr,value&0xffff);
    ptrace(PTRACE_POKEDATA,pid_me,addr+2,(value>>16)&0xffff);
    ptrace(PTRACE_POKEDATA,pid_me,addr+4,(value>>32)&0xffff);
    ptrace(PTRACE_POKEDATA,pid_me,addr+6,(value>>48)&0xffff);
}


void TikiDbg::dump_registers()
{
    for(const auto& rd:g_register_descriptors)
    {
        std::cout << rd.name << " 0x" << std::setfill('0') << std::setw(16)
            << std::hex << get_register_value(pid_me,rd.r) << std::endl;
    }
}

void TikiDbg::set_breakpoint_at_addr(std::intptr_t addr)
{
    Tikibreakpoint bp{pid_me,addr};
    bp.enable();
    t_breakpoints[addr]=bp;
    std::cout << "Set breakpoint at address 0x" << std::hex << addr << std::endl;

}


void TikiDbg::delete_breakpoint_at_addr(std::intptr_t addr)
{
    if(t_breakpoints.count(addr)!=0)
    {
        auto bp=t_breakpoints[addr];
        bp.disable();
        t_breakpoints.erase(addr);
        std::cout << "Delete breakpoint at address 0x" << std::hex << addr << std::endl;
    }
    else{
        std::cout << "No breakpoint at address 0x" << std::hex << addr << std::endl;
    }

}

void TikiDbg::run()
{
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &cs_handle) != CS_ERR_OK)
        throw std::runtime_error{"Couldn't open capstone"};
    

    wait_for_signal();
    initialise_load_address();
    char *line =nullptr;
    while((line=linenoise("TikiDbg> "))!=nullptr)
    {
        handle_command(line);
        linenoiseHistoryAdd(line);
        linenoiseFree(line);
    }

}

void TikiDbg::handle_command(const std::string& line)
{
    auto args = split(line, ' ');
    if(args.size()<=0)
    {
        return;
    }
    auto command = args[0];

    if(is_prefix(command,"continue"))
    {
        continue_execution();
    }
    else if(is_prefix(command,"break"))
    {
        if(args.size() == 2)
        {
            std::string addr {args[1]};
            uint64_t target_addr=0;
            if(addr[0]=='*')
            {//rebase address
                addr.erase(addr.begin());
                target_addr += std::stoll(addr,0,16)+binary_addr_base;
            }
            else{
                target_addr+=std::stoll(addr,0,16);
            }
            set_breakpoint_at_addr(target_addr);
        }
        else{
            std::cerr << "Unknown command " << command << std::endl;
        }
    }
    else if (is_prefix(command,"delete"))
    {
        if(args.size() == 2)
        {
            std::string addr {args[1]};
            delete_breakpoint_at_addr(std::stoll(addr,0,16));
        }
        else{
            std::cerr << "Unknown command " << command << std::endl;
        }
    }
    else if(is_prefix(command,"register"))
    {
        if(args.size()==1)
        {
            dump_registers();
        }
        else if(args.size()==2)
        {
            //register $rax
            std::string val {args[1]}; //assume 0xVAL
            if(val[0]=='$')
            {
                std::string reg_name(&val[1]);
                //set $rax 0xaaa
                
                uint64_t ret= get_register_value(pid_me,get_register_by_name(reg_name));
                std::cout << reg_name << ": "   << "0x" << std::hex << ret << std::endl;
            }
            else{
                std::cout << "Bad register" << std::endl;
            }
        }
        
    }
    else if(is_prefix(command,"set"))
    {
        //set $rax 0xaaaa
        std::string val {args[1]}; //assume 0xVAL
        std::string value {args[2]};
        if(val[0]=='$')
        {
            std::string reg_name(&val[1]);
            //set $rax 0xaaa
            uint64_t input=std::stoll(value,0,16);
            set_register_value(pid_me,get_register_by_name(reg_name),input);
            std::cout << "set $"<<reg_name << ": "   << "0x" << std::hex << input << std::endl;
        }
        else if(val[0]=='*')
        {
            //TODO: write memory
            std::string addr_s(&val[1]);
            uint64_t addr_input=std::stoll(addr_s,0,16);
            uint64_t value_input=std::stoll(value,0,16);
            write_memory(addr_input,value_input);
        }
    }
    else if(is_prefix(command,"memory")){
        //memory 0xaaaaa
        if(args.size() ==2)
        {
            std::string addr {args[1]};
            uint64_t addr_=std::stoll(addr,0,16);
            
            std::cout<<"0x" << std::setfill('0') << std::setw(16)<< std::hex << addr_<< ":  " <<
                std::setfill('0') << std::setw(16)<< read_memory(addr_) << std::endl;
        }
    }
    else if(is_prefix(command,"instep"))
    {
        single_step_instruction_with_breakpoint_check();
    }
    else if(is_prefix(command,"next"))
    {
        if( (read_memory(get_pc())&0xff) != 0xe8)
        {
            single_step_instruction_with_breakpoint_check();
        }
        else{
            uint8_t little_buf[16];
            uint64_t* temp_pointer=reinterpret_cast<uint64_t*>(little_buf);
            cs_insn *insn;
            uint64_t now_pc=get_pc();
            temp_pointer[0]=read_memory(now_pc);
            temp_pointer[1]=read_memory(now_pc+8);

            size_t count = cs_disasm(cs_handle, little_buf, 255, get_pc(), 2, &insn);
            if(count>0)
            {
                if(!std::strcmp(insn[0].mnemonic,"call"))
                {
                    set_breakpoint_at_addr(insn[1].address);
                    continue_execution();
                    delete_breakpoint_at_addr(insn[1].address);
                    set_pc(get_pc()-1);
                }
                cs_free(insn,count);
            }
        }

    }

    else{
        std::cerr << "Unknown command " << command << std::endl;
    }
}

void TikiDbg::continue_execution(){
    step_over_breakpoint();
    ptrace(PTRACE_CONT, pid_me, nullptr, nullptr);
    wait_for_signal();
}


std::vector<std::string> split(const std::string&s,char delim)
{
    std::vector<std::string> out{};
    std::stringstream ss {s};
    std::string item;

    while(std::getline(ss,item,delim))
    {
        out.push_back(item);
    }
    return out;
}

bool is_prefix(const std::string& s,const std::string&format)
{
    if(s.size()> format.size()) return false;
    return std::equal(s.begin(),s.end(),format.begin());
}


int main(int argc, char **argv)
{
    if(argc < 2)
    {
        std::cerr << "Usage: " << argv[0]<< " [program]"<<std::endl;
        return -1;
    }
    auto program = argv[1];
    auto pid = fork();
    if(pid==0)
    {// fork path
        ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
        execl(program, program, nullptr);
    }
    else if(pid>=1)
    {
        std::cout << "Started debugging process " << pid << '\n' << program << '\n';
        TikiDbg tikidbg{program, pid};
        personality(ADDR_NO_RANDOMIZE);
        tikidbg.run();
    }
}