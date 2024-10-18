#include "ini.hpp"


bool CIni::isValidNumber(const std::string& strNumber) {
    std::istringstream iss(strNumber);
    int nNum;

    return (iss >> nNum) && (iss.eof());
}


int CIni::SqlCallback(void* NotUsed, int argc, char** argv, char** azColName) {
    for (int i = 0; i < argc; i++) {
        std::cout << azColName[i] << " = " << (argv[i] ? argv[i] : "NULL") << std::endl;
    }
    std::cout << std::endl;
    return 0;
}