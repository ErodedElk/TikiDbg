#include <sys/personality.h>
#include "Tikidbg.h"
#include"Tikibreakpoint.h"
#include <unordered_map>
#include"TikiReg.h"
#include <iomanip>
#include"elf++.hh"
#include"dwarf++.hh"

class TikiDbg{
    public:
        TikiDbg(std::string program,pid_t pid): program_name{std::move(program)},pid_me{pid}{}

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
        void wait_for_signal();


    private:
        std::string program_name;
        pid_t pid_me;
        std::unordered_map<std::intptr_t,Tikibreakpoint> t_breakpoints;
};
void TikiDbg::wait_for_signal()
{
    int wait_status;
    auto options=0;
    waitpid(pid_me,&wait_status,options);
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
            ptrace(PTRACE_SINGLEBLOCK,pid_me,nullptr,nullptr);
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
    int wait_status = 0;
    auto options=0;
    waitpid(pid_me, &wait_status,options);
    
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
            set_breakpoint_at_addr(std::stoll(addr,0,16));
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