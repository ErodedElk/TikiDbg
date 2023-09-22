g++ -o tiki.o -g -c ../Tikidbg.cpp 
g++ -o bk.o -g -c ../Tikibreakpoint.cpp
g++ -o reg.o -g -c ../TikiReg.cpp
gcc -o line.o -g -c ../linenoise.c 
g++ bk.o tiki.o line.o  reg.o -o tiki ../libelfin/dwarf/libdwarf++.a  ../libelfin/elf/libelf++.a -lcapstone