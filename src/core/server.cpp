#include "server.h"
#include "room.h"
#include "../db/database.h"
#include "../net/session.h"

#include <chrono>
#include <iostream>

Server::Server() : db_(std::make_unique<Database>()) {}

Server::~Server() = default;

std::shared_ptr<Room> Server::get_or_create_room(const std::string& doc_id) {
    std::lock_guard<std::mutex> lock(rooms_mutex_);
    auto it = rooms_.find(doc_id);
    if (it == rooms_.end()) {
        auto r = std::make_shared<Room>(doc_id, *this);
        rooms_[doc_id] = r;
        return r;
    }
    return it->second;
}

void Server::register_user(const std::string& username, Session* session) {
    std::lock_guard<std::mutex> lock(user_mutex_);
    auto it = active_users_.find(username);
    if (it != active_users_.end() && it->second != session) {
        it->second->send(R"({"type": "kicked", "msg": "您的账号已在其他设备登录，您被迫下线！"})");
        std::cout << "用户 " << username << " 的旧设备被踢下线。" << std::endl;
    }
    active_users_[username] = session;
}

void Server::unregister_user(const std::string& username, Session* session) {
    std::lock_guard<std::mutex> lock(user_mutex_);
    auto it = active_users_.find(username);
    if (it != active_users_.end() && it->second == session) {
        active_users_.erase(it);
    }
}

bool Server::is_user_online(const std::string& username) {
    std::lock_guard<std::mutex> lock(user_mutex_);
    return active_users_.count(username) > 0;
}

Session* Server::get_user_session(const std::string& username) {
    std::lock_guard<std::mutex> lock(user_mutex_);
    auto it = active_users_.find(username);
    return it != active_users_.end() ? it->second : nullptr;
}

std::string Server::generate_doc_id(const std::string& username) {
    auto ts = std::chrono::steady_clock::now().time_since_epoch().count();
    return username + "_" + std::to_string(ts);
}

void Server::parse_invite_params(const json& data, const std::string& invite_type,
                                 int& max_uses, int64_t& expires_at) {
    max_uses = 1;
    expires_at = 0;
    if (invite_type == "permanent") {
        max_uses = -1;
    } else if (invite_type == "timed") {
        max_uses = -1;
        int hours = data.value("expire_hours", 24);
        auto now = std::chrono::system_clock::now().time_since_epoch();
        expires_at = std::chrono::duration_cast<std::chrono::seconds>(now).count() + hours * 3600;
    }
}
