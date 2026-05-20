#pragma once

#include "../common.h"

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

class Database;
class Room;

/**
 * @brief 顶层调度器：管理活跃房间、在线用户、生成 doc_id / 邀请类型解析。
 *
 * Server 不直接持有数据库句柄；所有持久化操作通过 db() 投递。
 */
class Server {
public:
    Server();
    ~Server();

    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;

    Database& db() { return *db_; }

    std::shared_ptr<Room> get_or_create_room(const std::string& doc_id);

    void register_user(const std::string& username, Session* session);
    void unregister_user(const std::string& username, Session* session);
    bool is_user_online(const std::string& username);
    Session* get_user_session(const std::string& username);

    std::string generate_doc_id(const std::string& username);
    static void parse_invite_params(const json& data, const std::string& invite_type,
                                    int& max_uses, int64_t& expires_at);

private:
    std::unique_ptr<Database> db_;

    std::unordered_map<std::string, std::shared_ptr<Room>> rooms_;
    std::mutex rooms_mutex_;

    std::unordered_map<std::string, Session*> active_users_;
    std::mutex user_mutex_;
};
