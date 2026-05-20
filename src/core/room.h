#pragma once

#include "../common.h"

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_set>

class Server;

/**
 * @brief 协作文档房间。
 *
 * 仅负责管理本房间内的 Session 集合、广播、历史回放与自动快照触发；
 * 实际的数据库操作通过 Server -> Database 投递。
 */
class Room {
public:
    Room(std::string doc_id, Server& server);

    void join(Session* session);
    void leave(Session* session);

    void broadcast_except(Session* sender, const std::string& message);
    void broadcast_all(const std::string& message);

    void send_history(Session* session);
    void save_event(const std::string& payload);
    void maybe_request_auto_snapshot();
    void reset_snapshot_state();

    uint32_t generate_site_id() { return next_site_id_++; }
    const std::string& doc_id() const { return doc_id_; }
    bool has_session(Session* session);

private:
    static constexpr int AUTO_SNAPSHOT_THRESHOLD = 500;

    std::string doc_id_;
    Server& server_;
    std::unordered_set<Session*> sessions_;
    std::mutex mutex_;
    uint32_t next_site_id_ = 1;
    int event_count_ = 0;
    bool snapshot_requested_ = false;
};
