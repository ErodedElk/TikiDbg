#include<stdio.h>
#include<iostream>

int main() {

    std::string name("0xbaaa");
    std::string name2(&name[1]);
    std::cout<<std::hex<< std::stoll(name,0,16) << std::endl;
    return 0;

}