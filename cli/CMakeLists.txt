add_executable(${PROJECT_NAME}
        cli.cpp
        ioc.cpp ioc.h
        policy.cpp policy.h
        policyDB.hpp)

target_link_libraries (${PROJECT_NAME} utility)
