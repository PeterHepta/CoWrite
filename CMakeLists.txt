cmake_minimum_required(VERSION 3.15)

set(CMAKE_TOOLCHAIN_FILE "/Users/mac/vcpkg/scripts/buildsystems/vcpkg.cmake" CACHE STRING "Vcpkg toolchain file")

project(CollaborativeDocServer CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(nlohmann_json CONFIG REQUIRED)
find_package(Boost REQUIRED COMPONENTS system)
find_package(Threads REQUIRED)
# 【新增】寻找 sqlite3
find_package(unofficial-sqlite3 CONFIG REQUIRED)

add_executable(DocServer src/main.cpp)

target_link_libraries(DocServer PRIVATE
    nlohmann_json::nlohmann_json
    Boost::boost
    Threads::Threads
    unofficial::sqlite3::sqlite3 # 【新增】链接 sqlite3
)

if (WIN32)
    target_link_libraries(DocServer PRIVATE wsock32 ws2_32)
endif()