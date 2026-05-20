#include "room.h"
#include "server.h"
#include "../db/database.h"
#include "../net/session.h"

#include <iostream>
#include <memory>

Room::Room(std::string doc_id, Server& server)
    : doc_id_(std::move(doc_id)), server_(server) {
    std::cout << "[Room] Document " << doc_id_ << " activated in memory." << std::endl;
}

void Room::join(Session* session) {
    std::lock_guard<std::mutex> lock(mutex_);
    sessions_.insert(session);
}

void Room::leave(Session* session) {
    std::lock_guard<std::mutex> lock(mutex_);
    sessions_.erase(session);
}

bool Room::has_session(Session* session) {
    std::lock_guard<std::mutex> lock(mutex_);
    return sessions_.count(session) > 0;
}

void Room::broadcast_except(Session* sender, const std::string& message) {
    auto shared_msg = std::make_shared<const std::string>(message);
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto* session : sessions_)
        if (session != sender) session->send_shared(shared_msg);
}

void Room::broadcast_all(const std::string& message) {
    auto shared_msg = std::make_shared<const std::string>(message);
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto* session : sessions_) session->send_shared(shared_msg);
}

void Room::save_event(const std::string& payload) {
    server_.db().push_event(doc_id_, payload);
    ++event_count_;
    maybe_request_auto_snapshot();
}

void Room::maybe_request_auto_snapshot() {
    if (event_count_ < AUTO_SNAPSHOT_THRESHOLD) return;
    std::lock_guard<std::mutex> lock(mutex_);
    if (snapshot_requested_) return;
    if (sessions_.empty()) return;
    snapshot_requested_ = true;
    Session* target = *sessions_.begin();
    std::string req = json{{"type", "request_auto_snapshot"}}.dump();
    target->send(req);
    std::cout << "[AutoSnap] 向客户端请求文档 " << doc_id_ << " 的自动快照 (events="
              << event_count_ << ")" << std::endl;
}

void Room::reset_snapshot_state() {
    event_count_ = 0;
    snapshot_requested_ = false;
    std::cout << "[AutoSnap] 房间 " << doc_id_ << " 快照状态已重置。" << std::endl;
}

void Room::send_history(Session* session) {
    Database* db_ref = &server_.db();
    std::string doc_id_copy = doc_id_;
    server_.db().post_task([session, db_ref, doc_id_copy]() {
        int64_t snap_rowid = 0;
        std::string snap_doc_state, snap_shapes;
        bool has_snap = false;
        {
            sqlite3_stmt* stmt = db_ref->stmt_get_latest_auto_snap_;
            sqlite3_reset(stmt);
            sqlite3_bind_text(stmt, 1, doc_id_copy.c_str(), -1, SQLITE_TRANSIENT);
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                snap_rowid = sqlite3_column_int64(stmt, 0);
                const char* ds = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
                const char* sh = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
                snap_doc_state = ds ? ds : "[]";
                snap_shapes    = sh ? sh : "[]";
                has_snap = true;
            }
        }

        if (has_snap) {
            json snap_msg = {{"type", "snapshot_init"},
                             {"doc_state", json::parse(snap_doc_state)},
                             {"shapes",    json::parse(snap_shapes)}};
            session->send(snap_msg.dump());

            sqlite3_stmt* stmt2 = db_ref->stmt_get_events_after_rowid_;
            sqlite3_reset(stmt2);
            sqlite3_bind_text(stmt2, 1, doc_id_copy.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(stmt2, 2, snap_rowid);
            json events = json::array();
            while (sqlite3_step(stmt2) == SQLITE_ROW) {
                const char* text = reinterpret_cast<const char*>(sqlite3_column_text(stmt2, 0));
                if (!text) continue;
                try { events.push_back(json::parse(text)); } catch (...) {}
            }
            if (!events.empty()) {
                std::string batch = json{{"type", "history_batch"}, {"events", std::move(events)}}.dump();
                session->send(batch);
            }
        } else {
            sqlite3_stmt* stmt = db_ref->stmt_get_history_;
            sqlite3_reset(stmt);
            sqlite3_bind_text(stmt, 1, doc_id_copy.c_str(), -1, SQLITE_TRANSIENT);
            json events = json::array();
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const char* text = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                if (!text) continue;
                try { events.push_back(json::parse(text)); } catch (...) {}
            }
            std::string batch = json{{"type", "history_batch"}, {"events", std::move(events)}}.dump();
            session->send(batch);
        }
    });
}
