
#g++ -g -O2 -Werror -std=c++0x -Wall $(pkg-config --cflags libelf++ libdwarf++) -MD -MP -MF .dump-sections.d   dump-sections.o ../dwarf/libdwarf++.a ../elf/libelf++.a   -o dump-sections
g++ -o tiki.o -g -c ../Tikidbg.cpp 
g++ bk.o tiki.o line.o  reg.o -o tiki ../libelfin/dwarf/libdwarf++.a  ../libelfin/elf/libelf++.a

