#pragma once

#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <sqlite3.h>

class CIni {
    public:
        bool isValidNumber(const std::string& strNumber);
        static int SqlCallback(void* NotUsed, int argc, char** argv, char** azColName);


};