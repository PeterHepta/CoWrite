cmake_minimum_required(VERSION 3.15)

if(EXISTS "/Users/mac/vcpkg/scripts/buildsystems/vcpkg.cmake")
    set(CMAKE_TOOLCHAIN_FILE "/Users/mac/vcpkg/scripts/buildsystems/vcpkg.cmake" CACHE STRING "Vcpkg toolchain file")
endif()

project(CollaborativeDocServer CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(nlohmann_json CONFIG REQUIRED)
find_package(Boost REQUIRED COMPONENTS system)
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

# 优先使用 vcpkg 的 unofficial-sqlite3，找不到时退回系统 libsqlite3-dev
find_package(unofficial-sqlite3 CONFIG QUIET)
if(NOT unofficial-sqlite3_FOUND)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(SQLITE3 REQUIRED IMPORTED_TARGET sqlite3)
endif()

add_executable(DocServer
    src/main.cpp
    src/util/sha256.cpp
    src/db/database.cpp
    src/core/room.cpp
    src/core/server.cpp
    src/net/session.cpp
    src/handlers/auth_handlers.cpp
    src/handlers/room_handlers.cpp
    src/handlers/room_admin_handlers.cpp
    src/handlers/snapshot_handlers.cpp
    src/handlers/message_handlers.cpp
)

target_link_libraries(DocServer PRIVATE
    nlohmann_json::nlohmann_json
    Boost::boost
    Threads::Threads
    OpenSSL::Crypto
)

if(unofficial-sqlite3_FOUND)
    target_link_libraries(DocServer PRIVATE unofficial::sqlite3::sqlite3)
else()
    target_link_libraries(DocServer PRIVATE PkgConfig::SQLITE3)
endif()

if (WIN32)
    target_link_libraries(DocServer PRIVATE wsock32 ws2_32)
endif()