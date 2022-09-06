#pragma once

#include <string_view>
#include <sstream>
#include <string>
#include <memory>
#include "db.h"
#include "policy.h"

#define TABLENAME "POLICY"

#define MAKE_TUPLE(p)                                                                           \
    std::make_tuple(                                                                            \
        static_cast<std::underlying_type_t<decltype(p.dest)>>(p.dest),                          \
        p.dest == Hf::Policy::DestType::INPUT ?                                                 \
            (!p.interface.in.empty() ? p.interface.in: "null"): (!p.interface.out.empty() ?     \
                p.interface.out: "null"),                                                       \
        static_cast<std::underlying_type_t<decltype(p.pro)>>(p.pro) != 0 ?                      \
            static_cast<std::underlying_type_t<decltype(p.pro)>>(p.pro) : 0,                    \
        !p.mac.src.empty() ? p.mac.src : "null",                                                \
        p.dest == Hf::Policy::DestType::INPUT ?                                                 \
            (p.ipaddr.src ? p.ipaddr.src : 0): (p.ipaddr.dest ? p.ipaddr.dest : 0),             \
        p.port.src ? p.port.src : 0,                                                            \
        p.port.dest ? p.port.dest : 0,                                                          \
        static_cast<std::underlying_type_t<decltype(p.target)>>(p.target)                       \
    )


namespace Hf {

template<typename T>
std::string unpack(T&& t) {
    std::stringstream ss;
    ss << "," << std::get<0>(std::forward<T>(t)) << " " << std::get<1>(std::forward<T>(t));
    return ss.str();
}

template<typename T, typename... Rest>
std::string unpack(T&& t, Rest&& ... rest) {
    return unpack(std::forward<T>(t)) + unpack(std::forward<Rest>(rest)...);
}

class PolicyDB {
public:
    PolicyDB() : m_db(std::make_unique<Utility::SQLiteDB>(m_dbName)) {}

    template<typename ... Params>
    void createTable(std::string_view tableName, Params&& ...params);

    template<typename ... Params>
    void insert(std::string_view tableName, std::tuple<Params...> p);

    template<typename ... Params>
    void read(std::string_view tableName, std::tuple<Params...> p);

    template<typename ... Params>
    void del(std::string_view tableName, std::tuple<Params...> p);

    void flush(std::string_view tableName);

    void changes(std::string_view tableName);

private:
    std::unique_ptr<Utility::DB> m_db;
    static constexpr char* const m_dbName = (char*) "hellfire.db";

};

template<typename... Params>
void PolicyDB::createTable(std::string_view tableName, Params&& ... params) {
    std::stringstream ss;
    ss << "CREATE TABLE IF NOT EXISTS " << tableName << "(";
    ss << "ID INTEGER PRIMARY KEY AUTOINCREMENT";
    ss << unpack(std::forward<Params>(params)...);
    ss << ");";

    m_db->exec(ss.str().c_str(), nullptr);

}

template<typename ... Params>
void PolicyDB::insert(std::string_view tableName, std::tuple<Params...> p) {
    std::stringstream ss;
    ss << "INSERT INTO " << tableName << "(DEST,INTERFACE,PROTOCOL,MAC,IP,SPT,DPT,TARGET)" << " VALUES(";
    ss << std::get<0>(p) << ","
       << "'" << std::get<1>(p) << "'" << ","
       << std::get<2>(p) << ","
       << "'" << std::get<3>(p) << "'" << ","
       << std::get<4>(p) << ","
       << std::get<5>(p) << ","
       << std::get<6>(p) << ","
       << std::get<7>(p);
    ss << ");";

    m_db->exec(ss.str().c_str(), nullptr);
}

template<typename... Params>
void PolicyDB::read(std::string_view tableName, std::tuple<Params...> p) {
    std::stringstream ss;
    ss << "SELECT * FROM " << tableName << " WHERE ";
    ss << "DEST=" << std::get<0>(p);
    if (std::get<1>(p) != "null") {
        ss << " AND INTERFACE=" << "'" << std::get<1>(p) << "'";
    }
    if (std::get<2>(p)) {
        ss << " AND PROTOCOL=" << std::get<2>(p);
    }
    if (std::get<3>(p) != "null") {
        ss << " AND MAC=" << "'" << std::get<3>(p) << "'";
    }
    if (std::get<4>(p)) {
        ss << " AND IP=" << std::get<4>(p);
    }
    if (std::get<5>(p)) {
        ss << " AND SPT=" << std::get<5>(p);
    }
    if (std::get<6>(p)) {
        ss << " AND DPT=" << std::get<6>(p);
    }
    if (std::get<7>(p)) {
        ss << " AND TARGET=" << std::get<7>(p);
    }
    m_db->exec(ss.str().c_str(), [](void* data, int argc, char** argv, char** colName) {
        for (int i = 0; i < argc; i++) {
            std::string_view arg{argv[i]};
            if (!arg.empty()) {
                if (!std::strcmp(colName[i], "DEST")) {
                    arg = Hf::toDestPf(arg);
                } else if (!std::strcmp(colName[i], "TARGET")) {
                    arg = Hf::toTargetPf(arg);
                } else if (!std::strcmp(colName[i], "IP")) {
                    arg = Hf::Utility::Ip::inet_pf(std::stol(arg.data()));
                }
            }
            std::cout << colName[i] << "=" << (!arg.empty() ? arg : "null") << " ";
        }
        std::cout << "\n";
        return 0;
    });
}

template<typename... Params>
void PolicyDB::del(std::string_view tableName, std::tuple<Params...> p) {
    std::stringstream ss;
    ss << "DELETE FROM " << tableName << " WHERE ";
    ss << "DEST=" << std::get<0>(p);
    if (std::get<1>(p) != "null") {
        ss << " AND INTERFACE=" << "'" << std::get<1>(p) << "'";
    }
    if (std::get<2>(p)) {
        ss << " AND PROTOCOL=" << std::get<2>(p);
    }
    if (std::get<3>(p) != "null") {
        ss << " AND MAC=" << "'" << std::get<3>(p) << "'";
    }
    if (std::get<4>(p)) {
        ss << " AND IP=" << std::get<4>(p);
    }
    if (std::get<5>(p)) {
        ss << " AND SPT=" << std::get<5>(p);
    }
    if (std::get<6>(p)) {
        ss << " AND DPT=" << std::get<6>(p);
    }
    if (std::get<7>(p)) {
        ss << " AND TARGET=" << std::get<7>(p);
    }
    m_db->exec(ss.str().c_str(), nullptr);
}

void PolicyDB::flush(std::string_view tableName) {
    std::stringstream ss;
    ss << "DELETE FROM " << tableName;
    m_db->exec(ss.str().c_str(), nullptr);
}

void PolicyDB::changes(std::string_view tableName) {
    std::string_view sw = "SELECT changes();";
    m_db->exec(sw.data(), [](void* data, int argc, char** argv, char** colName) {
        for (int i = 0; i < argc; i++) {
            std::cout << colName[i] << "=" << (argv[i] ? argv[i] : "NULL") << " ";
        }
        std::cout << "\n";
        return 0;
    });
}
}
