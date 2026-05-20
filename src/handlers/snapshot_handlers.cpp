#include "../net/session.h"
#include "../core/server.h"
#include "../core/room.h"
#include "../db/database.h"

#include <sqlite3.h>
#include <chrono>
#include <iostream>

void Session::handle_save_snapshot(const json& data, const std::string& /*raw*/) {
    bool is_quick = (data.value("type", "") == "quicksave_snapshot");
    std::string save_name = is_quick ? "快速存档" : data.value("name", "默认存档");
    std::string doc_state = data.value("doc_state", "[]");
    std::string shapes_str = data.value("shapes", "[]");
    std::string uname = username_;
    std::string doc_id = room_->doc_id();
    auto self = shared_from_this();
    server_.db().post_task([this, self, is_quick, save_name, doc_state, shapes_str, uname, doc_id]() {
        if (is_quick) {
            sqlite3_reset(server_.db().stmt_delete_quick_save_);
            sqlite3_bind_text(server_.db().stmt_delete_quick_save_, 1, doc_id.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(server_.db().stmt_delete_quick_save_);
        }
        sqlite3_reset(server_.db().stmt_insert_save_);
        sqlite3_bind_text(server_.db().stmt_insert_save_, 1, doc_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(server_.db().stmt_insert_save_, 2, uname.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(server_.db().stmt_insert_save_, 3, save_name.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(server_.db().stmt_insert_save_,  4, is_quick ? 1 : 0);
        sqlite3_bind_text(server_.db().stmt_insert_save_, 5, doc_state.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(server_.db().stmt_insert_save_, 6, shapes_str.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(server_.db().stmt_insert_save_);
        int64_t new_id = sqlite3_last_insert_rowid(server_.db().handle());
        auto now = std::chrono::system_clock::now().time_since_epoch();
        int64_t ts = std::chrono::duration_cast<std::chrono::seconds>(now).count();
        json res = {{"type","save_snapshot_res"},{"success",true},
                    {"id",new_id},{"name",save_name},
                    {"created_at",ts},{"is_quick",is_quick}};
        std::string resp = res.dump();
        net::post(ws_.get_executor(), [self, resp]() { self->send(resp); });
    });
}

void Session::handle_get_saves(const json& /*data*/, const std::string& /*raw*/) {
    std::string doc_id = room_->doc_id();
    auto self = shared_from_this();
    server_.db().post_task([this, self, doc_id]() {
        sqlite3_reset(server_.db().stmt_get_saves_);
        sqlite3_bind_text(server_.db().stmt_get_saves_, 1, doc_id.c_str(), -1, SQLITE_TRANSIENT);
        json saves = json::array();
        while (sqlite3_step(server_.db().stmt_get_saves_) == SQLITE_ROW) {
            auto col_text = [&](int col) -> std::string {
                const char* t = reinterpret_cast<const char*>(
                    sqlite3_column_text(server_.db().stmt_get_saves_, col));
                return t ? t : "";
            };
            json s;
            s["id"]         = sqlite3_column_int64(server_.db().stmt_get_saves_, 0);
            s["created_by"] = col_text(1);
            s["name"]       = col_text(2);
            s["is_quick"]   = (sqlite3_column_int(server_.db().stmt_get_saves_, 3) == 1);
            s["created_at"] = sqlite3_column_int64(server_.db().stmt_get_saves_, 4);
            saves.push_back(s);
        }
        json res = {{"type","get_saves_res"},{"success",true},{"saves",saves}};
        std::string resp = res.dump();
        net::post(ws_.get_executor(), [self, resp]() { self->send(resp); });
    });
}

void Session::handle_load_save(const json& data, const std::string& /*raw*/) {
    int64_t save_id = data.value("save_id", (int64_t)0);
    std::string doc_id = room_->doc_id();
    std::string uname = username_;
    auto self = shared_from_this();
    auto room_ref = room_;
    server_.db().post_task([this, self, room_ref, save_id, doc_id, uname]() {
        sqlite3_reset(server_.db().stmt_get_save_by_id_);
        sqlite3_bind_int64(server_.db().stmt_get_save_by_id_, 1, save_id);
        sqlite3_bind_text(server_.db().stmt_get_save_by_id_, 2, doc_id.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(server_.db().stmt_get_save_by_id_) != SQLITE_ROW) {
            net::post(ws_.get_executor(), [self]() {
                self->send(R"({"type":"load_save_res","success":false,"msg":"存档不存在"})");
            });
            return;
        }
        auto col_text = [&](int col) -> std::string {
            const char* t = reinterpret_cast<const char*>(
                sqlite3_column_text(server_.db().stmt_get_save_by_id_, col));
            return t ? t : "";
        };
        std::string save_name = col_text(0);
        std::string doc_state_str = col_text(1);
        std::string shapes_str = col_text(2);

        json doc_state_json = json::array();
        json shapes_json = json::array();
        try { doc_state_json = json::parse(doc_state_str); } catch(...) {}
        try { shapes_json = json::parse(shapes_str); } catch(...) {}

        sqlite3_reset(server_.db().stmt_clear_events_);
        sqlite3_bind_text(server_.db().stmt_clear_events_, 1, doc_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(server_.db().stmt_clear_events_);

        for (const auto& item : doc_state_json) {
            try {
                json ev = {{"type","insert"},
                           {"id", item.at("id")},
                           {"char", item.at("char")},
                           {"attributes", item.value("attributes", json::object())}};
                std::string payload = ev.dump();
                sqlite3_reset(server_.db().stmt_insert_event_);
                sqlite3_bind_text(server_.db().stmt_insert_event_, 1, doc_id.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(server_.db().stmt_insert_event_, 2, payload.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_step(server_.db().stmt_insert_event_);
            } catch(...) {}
        }

        for (const auto& s : shapes_json) {
            try {
                json ev = {{"type","shape_add"}, {"shape", s}};
                std::string payload = ev.dump();
                sqlite3_reset(server_.db().stmt_insert_event_);
                sqlite3_bind_text(server_.db().stmt_insert_event_, 1, doc_id.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(server_.db().stmt_insert_event_, 2, payload.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_step(server_.db().stmt_insert_event_);
            } catch(...) {}
        }

        json broadcast_msg;
        broadcast_msg["type"] = "load_save_applied";
        broadcast_msg["save_id"] = save_id;
        broadcast_msg["name"] = save_name;
        broadcast_msg["applied_by"] = uname;
        broadcast_msg["doc_state"] = doc_state_json;
        broadcast_msg["shapes"] = shapes_json;
        std::string resp = broadcast_msg.dump();
        net::post(ws_.get_executor(), [room_ref, resp]() {
            room_ref->broadcast_all(resp);
        });
    });
}

void Session::handle_delete_save(const json& data, const std::string& /*raw*/) {
    int64_t save_id = data.value("save_id", (int64_t)0);
    std::string doc_id = room_->doc_id();
    auto self = shared_from_this();
    auto room_ref = room_;
    server_.db().post_task([this, self, room_ref, save_id, doc_id]() {
        sqlite3_reset(server_.db().stmt_delete_save_);
        sqlite3_bind_int64(server_.db().stmt_delete_save_, 1, save_id);
        sqlite3_bind_text(server_.db().stmt_delete_save_, 2, doc_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(server_.db().stmt_delete_save_);
        json res = {{"type","delete_save_res"},{"success",true},{"save_id",save_id}};
        std::string resp_sender = res.dump();
        json bcast = {{"type","save_deleted"},{"save_id",save_id}};
        std::string resp_bcast = bcast.dump();
        net::post(ws_.get_executor(), [self, room_ref, resp_sender, resp_bcast]() {
            self->send(resp_sender);
            room_ref->broadcast_except(self.get(), resp_bcast);
        });
    });
}

void Session::handle_submit_auto_snapshot(const json& data, const std::string& /*raw*/) {
    std::string doc_state = data.value("doc_state", "[]");
    std::string shapes_str = data.value("shapes", "[]");
    std::string uname = username_;
    std::string doc_id = room_->doc_id();
    auto room_ref = room_;
    auto self = shared_from_this();
    server_.db().post_task([this, self, room_ref, doc_id, uname, doc_state, shapes_str]() {
        sqlite3_reset(server_.db().stmt_insert_auto_snap_);
        sqlite3_bind_text(server_.db().stmt_insert_auto_snap_, 1, doc_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(server_.db().stmt_insert_auto_snap_, 2, uname.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(server_.db().stmt_insert_auto_snap_, 3, "auto_snapshot", -1, SQLITE_STATIC);
        sqlite3_bind_text(server_.db().stmt_insert_auto_snap_, 4, doc_state.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(server_.db().stmt_insert_auto_snap_, 5, shapes_str.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(server_.db().stmt_insert_auto_snap_);

        sqlite3_reset(server_.db().stmt_clear_events_);
        sqlite3_bind_text(server_.db().stmt_clear_events_, 1, doc_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(server_.db().stmt_clear_events_);

        sqlite3_reset(server_.db().stmt_delete_old_auto_snaps_);
        sqlite3_bind_text(server_.db().stmt_delete_old_auto_snaps_, 1, doc_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(server_.db().stmt_delete_old_auto_snaps_, 2, doc_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(server_.db().stmt_delete_old_auto_snaps_);

        std::cout << "[AutoSnap] 文档 " << doc_id
                  << " 自动快照已保存，events 表已清空。" << std::endl;

        net::post(ws_.get_executor(), [room_ref]() {
            room_ref->reset_snapshot_state();
        });
    });
}
