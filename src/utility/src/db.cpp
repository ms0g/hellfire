#include "db.h"
#include <iostream>

namespace Hf::Utility {

SQLiteDB::SQLiteDB(std::string_view dbName) {
    if (sqlite3_open(dbName.data(), &m_db) != 0) {
        std::cerr << dbName << ": Cannot open database " << sqlite3_errmsg(m_db);
        return;
    }

    std::cout << dbName << ": Database opened successfully" << std::endl;
}

SQLiteDB::~SQLiteDB() {
    sqlite3_close(m_db);
}

void SQLiteDB::exec(std::string_view query, int (* callback)(void*, int, char**, char**)) {
    if (sqlite3_exec(m_db, query.data(), callback, nullptr, &m_errMsg) != SQLITE_OK) {
        std::cerr <<  "DB: Error exec" << std::endl;
        sqlite3_free(m_errMsg);
    }
}

}
