#pragma once

#include <mutex>
#include <sqlite3.h>

#include "ini.hpp"


constexpr const char* CHECK_IP_QUERY = "SELECT ip FROM FirewallRules WHERE ip = ? LIMIT 1";



class CConfigDB {
public:
    CConfigDB();
    ~CConfigDB();
    bool CheckIPinDB(const std::string& ip);

private:
    sqlite3* m_db;
    std::mutex m_dbMutex;
    int m_nRc; //database의 상태를 저장하는 변수
};