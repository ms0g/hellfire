#pragma once

#include <sqlite3.h>
#include <string_view>

namespace Hf::Utility {

class DB {
public:
    virtual ~DB() = 0;

    virtual void exec(std::string_view query, int (* callback)(void*, int, char**, char**)) = 0;
};

DB::~DB() = default;

class SQLiteDB : public DB {
public:
    explicit SQLiteDB(std::string_view dbName);

    ~SQLiteDB() override;

    void exec(std::string_view query, int (* callback)(void*, int, char**, char**)) override;

private:
    sqlite3* m_db{};
    char* m_errMsg{};

};
}
