#include<iostream>
#include<unistd.h>
#include<sys/types.h>
#include<sys/ptrace.h>
#include <sys/wait.h>

#include<stdlib.h>
#include "linenoise.h"
#include<vector>

#include <sstream>


bool is_prefix(const std::string& s,const std::string&format);

std::vector<std::string> split(const std::string&s,char delim);