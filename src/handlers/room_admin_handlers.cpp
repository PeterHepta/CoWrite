#include "../net/session.h"
#include "../core/server.h"
#include "../core/room.h"
#include "../db/database.h"

#include <sqlite3.h>
#include <iostream>
#include <vector>

void Session::handle_gen_invite(const json& data, const std::string& /*raw*/) {
    std::string invite_type = data.value("invite_type", "once");
    int max_uses; int64_t expires_at;
    Server::parse_invite_params(data, invite_type, max_uses, expires_at);
    std::string uname = username_;
    std::string doc_id = room_->doc_id();
    auto self = shared_from_this();
    server_.db().post_task([this, self, uname, doc_id, invite_type, max_uses, expires_at]() {
        if (!server_.db().check_is_owner(doc_id, uname)) {
            net::post(ws_.get_executor(), [self]() {
                self->send(R"({"type":"gen_invite_res","success":false,"msg":"只有房间创建者才能生成邀请码"})");
            });
            return;
        }

        std::string code = server_.db().generate_unique_code();
        std::string room_name = server_.db().query_room_name(doc_id);
        if (room_name.empty()) room_name = "未命名房间";
        server_.db().insert_invite(code, doc_id, room_name, uname, max_uses, expires_at);

        json res = {{"type", "gen_invite_res"}, {"success", true},
                    {"code", code}, {"invite_type", invite_type}};
        if (expires_at > 0) res["expires_at"] = expires_at;
        std::string resp = res.dump();
        std::cout << "用户 " << uname << " 在房间 " << doc_id
                  << " 生成新邀请码: " << code << " [" << invite_type << "]" << std::endl;
        net::post(ws_.get_executor(), [self, resp]() { self->send(resp); });
    });
}

void Session::handle_rename_room(const json& data, const std::string& /*raw*/) {
    std::string new_name = data.value("room_name", "");
    if (new_name.empty()) {
        send(R"({"type":"rename_room_res","success":false,"msg":"房间名不能为空"})");
        return;
    }
    std::string uname = username_;
    std::string doc_id = room_->doc_id();
    auto self = shared_from_this();
    server_.db().post_task([this, self, uname, doc_id, new_name]() {
        if (!server_.db().check_is_owner(doc_id, uname)) {
            net::post(ws_.get_executor(), [self]() {
                self->send(R"({"type":"rename_room_res","success":false,"msg":"只有房间创建者才能修改房间名"})");
            });
            return;
        }
        sqlite3_reset(server_.db().stmt_update_room_name_);
        sqlite3_bind_text(server_.db().stmt_update_room_name_, 1, new_name.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(server_.db().stmt_update_room_name_, 2, doc_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(server_.db().stmt_update_room_name_);

        json res = {{"type", "rename_room_res"}, {"success", true}, {"room_name", new_name}};
        std::string resp = res.dump();
        std::cout << "用户 " << uname << " 将房间 " << doc_id
                  << " 重命名为: " << new_name << std::endl;
        net::post(ws_.get_executor(), [self, resp]() { self->send(resp); });
    });
}

void Session::handle_get_room_members(const json& /*data*/, const std::string& /*raw*/) {
    std::string doc_id = room_->doc_id();
    auto self = shared_from_this();
    server_.db().post_task([this, self, doc_id]() {
        std::string room_owner;
        {
            sqlite3_reset(server_.db().stmt_get_owner_);
            sqlite3_bind_text(server_.db().stmt_get_owner_, 1, doc_id.c_str(), -1, SQLITE_TRANSIENT);
            if (sqlite3_step(server_.db().stmt_get_owner_) == SQLITE_ROW)
                room_owner = reinterpret_cast<const char*>(
                    sqlite3_column_text(server_.db().stmt_get_owner_, 0));
        }
        sqlite3_reset(server_.db().stmt_get_members_);
        sqlite3_bind_text(server_.db().stmt_get_members_, 1, doc_id.c_str(), -1, SQLITE_TRANSIENT);
        std::vector<std::string> unames;
        while (sqlite3_step(server_.db().stmt_get_members_) == SQLITE_ROW)
            unames.push_back(reinterpret_cast<const char*>(
                sqlite3_column_text(server_.db().stmt_get_members_, 0)));

        net::post(ws_.get_executor(), [self, this, unames, room_owner]() {
            json members = json::array();
            for (const auto& uname : unames) {
                json m;
                m["username"] = uname;
                m["is_owner"] = (uname == room_owner);
                Session* user_session = server_.get_user_session(uname);
                if (user_session && room_ && room_->has_session(user_session)) {
                    m["status"] = "in_room";
                } else if (user_session) {
                    m["status"] = "online";
                } else {
                    m["status"] = "offline";
                }
                members.push_back(m);
            }
            json res = {{"type", "get_room_members_res"}, {"success", true}, {"members", members}};
            self->send(res.dump());
        });
    });
}
