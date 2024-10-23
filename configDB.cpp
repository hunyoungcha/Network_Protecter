#include "configDB.hpp"


CConfigDB::CConfigDB() {
    m_nRc = sqlite3_open("firewall.db", &m_db);
    if (m_nRc) {
        std::cerr << "Can't open database: " << sqlite3_errmsg(m_db) << std::endl;
    }
}

CConfigDB::~CConfigDB() {
    if (m_db) {
        sqlite3_close(m_db);
    }
}


// DB 데이터 select 함수
bool CConfigDB::CheckIPinDB(const std::string& ip) {
    std::lock_guard<std::mutex> lock(m_dbMutex);
    sqlite3_stmt* stmt;
    
    char* errMsg = 0;
    
    if (sqlite3_prepare_v2(m_db, CHECK_IP_QUERY, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "ERROR : " << sqlite3_errmsg(m_db) << std::endl;
        return false;
    }

    sqlite3_bind_text(stmt, 1, ip.c_str(), -1, SQLITE_STATIC);

    int result = sqlite3_step(stmt);
    bool found = (result == SQLITE_ROW);

    sqlite3_finalize(stmt);

    return found;
}


