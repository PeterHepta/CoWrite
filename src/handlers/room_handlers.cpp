#include "../net/session.h"
#include "../core/server.h"
#include "../core/room.h"
#include "../db/database.h"

#include <sqlite3.h>
#include <chrono>
#include <iostream>

void Session::handle_create_room(const json& data, const std::string& /*raw*/) {
    if (username_.empty()) {
        send(R"({"type":"create_room_res","success":false,"msg":"请先登录"})");
        return;
    }
    std::string doc_id = server_.generate_doc_id(username_);
    std::string room_name = data.value("room_name", "未命名房间");
    std::string invite_type = data.value("invite_type", "once");
    int max_uses; int64_t expires_at;
    Server::parse_invite_params(data, invite_type, max_uses, expires_at);
    std::string uname = username_;
    auto self = shared_from_this();
    server_.db().post_task([this, self, doc_id, room_name, invite_type, max_uses, expires_at, uname]() {
        std::string code = server_.db().generate_unique_code();
        server_.db().insert_invite(code, doc_id, room_name, uname, max_uses, expires_at);

        json res = {{"type", "create_room_res"}, {"success", true},
                    {"code", code}, {"doc_id", doc_id},
                    {"room_name", room_name}, {"invite_type", invite_type}};
        if (expires_at > 0) res["expires_at"] = expires_at;
        std::string resp = res.dump();
        std::cout << "用户 " << uname << " 创建房间 [" << room_name << "] "
                  << doc_id << "，邀请码: " << code << " [" << invite_type << "]" << std::endl;
        net::post(ws_.get_executor(), [self, resp]() { self->send(resp); });
    });
}

void Session::handle_join_with_code(const json& data, const std::string& /*raw*/) {
    std::string code = data.value("code", "");
    if (username_.empty()) {
        send(R"({"type":"join_with_code_res","success":false,"msg":"请先登录"})");
        return;
    }
    if (code.empty()) {
        send(R"({"type":"join_with_code_res","success":false,"msg":"邀请码不能为空"})");
        return;
    }
    std::string uname = username_;
    auto self = shared_from_this();
    server_.db().post_task([this, self, code, uname]() {
        sqlite3_reset(server_.db().stmt_join_with_code_);
        sqlite3_bind_text(server_.db().stmt_join_with_code_, 1, code.c_str(), -1, SQLITE_TRANSIENT);
        json res = {{"type", "join_with_code_res"}};
        if (sqlite3_step(server_.db().stmt_join_with_code_) == SQLITE_ROW) {
            std::string doc_id = reinterpret_cast<const char*>(sqlite3_column_text(server_.db().stmt_join_with_code_, 0));
            std::string room_name = reinterpret_cast<const char*>(sqlite3_column_text(server_.db().stmt_join_with_code_, 1));
            int max_uses = sqlite3_column_int(server_.db().stmt_join_with_code_, 2);
            bool has_expiry = (sqlite3_column_type(server_.db().stmt_join_with_code_, 3) != SQLITE_NULL);
            int64_t expires_at = has_expiry ? sqlite3_column_int64(server_.db().stmt_join_with_code_, 3) : 0;

            if (has_expiry) {
                auto now = std::chrono::system_clock::now().time_since_epoch();
                int64_t now_sec = std::chrono::duration_cast<std::chrono::seconds>(now).count();
                if (now_sec > expires_at) {
                    res["success"] = false; res["msg"] = "邀请码已过期";
                    std::string resp = res.dump();
                    net::post(ws_.get_executor(), [self, resp]() { self->send(resp); });
                    return;
                }
            }
            if (max_uses == 1) {
                sqlite3_reset(server_.db().stmt_use_code_);
                sqlite3_bind_text(server_.db().stmt_use_code_, 1, code.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_step(server_.db().stmt_use_code_);
            }
            res["success"] = true; res["doc_id"] = doc_id; res["room_name"] = room_name;
            std::cout << "用户 " << uname << " 使用邀请码 " << code << " 加入房间 " << doc_id << std::endl;
        } else {
            res["success"] = false; res["msg"] = "邀请码无效或已被使用";
        }
        std::string resp = res.dump();
        net::post(ws_.get_executor(), [self, resp]() { self->send(resp); });
    });
}

void Session::handle_join(const json& data, const std::string& /*raw*/) {
    std::string doc_id = data.value("doc_id", "public_room");
    room_ = server_.get_or_create_room(doc_id);
    int req_site = data.value("requested_site_id", 0);
    if (req_site > 0) site_id_ = req_site;
    else site_id_ = room_->generate_site_id();

    room_->join(this);
    joined_ = true;

    std::string uname = username_;
    uint32_t sid = site_id_;
    auto self = shared_from_this();
    auto room_ref = room_;
    server_.db().post_task([this, self, room_ref, doc_id, uname, sid]() {
        sqlite3_reset(server_.db().stmt_insert_member_);
        sqlite3_bind_text(server_.db().stmt_insert_member_, 1, uname.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(server_.db().stmt_insert_member_, 2, doc_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(server_.db().stmt_insert_member_);

        std::string room_name = server_.db().query_room_name(doc_id);

        net::post(ws_.get_executor(), [self, this, room_ref, room_name, sid, uname]() {
            json init_msg = {{"type", "init"}, {"site_id", sid}, {"room_name", room_name}};
            self->send(init_msg.dump());
            room_ref->send_history(this);
            json presence_msg = {{"type", "presence"}, {"action", "join"},
                                 {"site_id", sid}, {"username", uname}};
            room_ref->broadcast_except(this, presence_msg.dump());
        });
    });
}

void Session::handle_get_my_rooms(const json& /*data*/, const std::string& /*raw*/) {
    if (username_.empty()) {
        send(R"({"type":"get_my_rooms_res","success":false,"msg":"请先登录"})");
        return;
    }
    std::string uname = username_;
    auto self = shared_from_this();
    server_.db().post_task([this, self, uname]() {
        sqlite3_reset(server_.db().stmt_get_my_rooms_);
        sqlite3_bind_text(server_.db().stmt_get_my_rooms_, 1, uname.c_str(), -1, SQLITE_TRANSIENT);
        json rooms = json::array();
        while (sqlite3_step(server_.db().stmt_get_my_rooms_) == SQLITE_ROW) {
            json r;
            auto col_text = [&](int col) -> std::string {
                const char* t = reinterpret_cast<const char*>(
                    sqlite3_column_text(server_.db().stmt_get_my_rooms_, col));
                return t ? t : "";
            };
            r["doc_id"]     = col_text(0);
            r["room_name"]  = col_text(1);
            r["created_by"] = col_text(2);
            r["created_at"] = sqlite3_column_int64(server_.db().stmt_get_my_rooms_, 3);
            r["joined_at"]  = sqlite3_column_int64(server_.db().stmt_get_my_rooms_, 4);
            rooms.push_back(r);
        }
        std::string resp = json{{"type", "get_my_rooms_res"}, {"success", true}, {"rooms", rooms}}.dump();
        net::post(ws_.get_executor(), [self, resp]() { self->send(resp); });
    });
}

void Session::handle_rejoin_room(const json& data, const std::string& /*raw*/) {
    std::string doc_id = data.value("doc_id", "");
    if (username_.empty()) {
        send(R"({"type":"rejoin_room_res","success":false,"msg":"请先登录"})");
        return;
    }
    if (doc_id.empty()) {
        send(R"({"type":"rejoin_room_res","success":false,"msg":"doc_id 不能为空"})");
        return;
    }
    std::string uname = username_;
    int req_site = data.value("requested_site_id", 0);
    auto self = shared_from_this();
    server_.db().post_task([this, self, doc_id, uname, req_site]() {
        sqlite3_reset(server_.db().stmt_check_member_);
        sqlite3_bind_text(server_.db().stmt_check_member_, 1, uname.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(server_.db().stmt_check_member_, 2, doc_id.c_str(), -1, SQLITE_TRANSIENT);
        bool is_member = (sqlite3_step(server_.db().stmt_check_member_) == SQLITE_ROW);

        if (!is_member) {
            net::post(ws_.get_executor(), [self]() {
                self->send(R"({"type":"rejoin_room_res","success":false,"msg":"您没有该房间的访问权限"})");
            });
            return;
        }

        std::string room_name = server_.db().query_room_name(doc_id);

        net::post(ws_.get_executor(), [self, this, doc_id, room_name, req_site, uname]() {
            room_ = server_.get_or_create_room(doc_id);
            if (req_site > 0) site_id_ = req_site;
            else site_id_ = room_->generate_site_id();
            room_->join(this);
            joined_ = true;

            json init_msg = {{"type", "init"}, {"site_id", site_id_}, {"room_name", room_name}};
            self->send(init_msg.dump());
            room_->send_history(this);
            json presence_msg = {{"type","presence"},{"action","join"},
                                 {"site_id", site_id_},{"username", uname}};
            room_->broadcast_except(this, presence_msg.dump());
        });
    });
}
