#include "ini.hpp"


bool CIni::isValidNumber(const std::string& strNumber) {
    std::istringstream iss(strNumber);
    int nNum;

    return (iss >> nNum) && (iss.eof());
}