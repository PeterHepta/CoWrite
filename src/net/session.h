#pragma once

#include "../common.h"

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

class Server;
class Room;

/**
 * @brief WebSocket 客户端连接。
 *
 * 负责：消息读取、批量写入、按 joined_ 状态把消息派发给对应 handler。
 * 所有 handler 都是 Session 的成员函数（定义分散在 handlers/ 下的 cpp）。
 */
class Session : public std::enable_shared_from_this<Session> {
public:
    Session(tcp::socket&& socket, Server& server);
    ~Session();

    void run();

    // 线程安全：由 Room 广播 / handler 调用
    void send(const std::string& message);
    void send_shared(std::shared_ptr<const std::string> message);

private:
    using HandlerFn = void (Session::*)(const json& data, const std::string& raw);
    using HandlerTable = std::unordered_map<std::string, HandlerFn>;

    void on_run();
    void on_accept(beast::error_code ec);
    void do_read();
    void on_read(beast::error_code ec, std::size_t bytes_transferred);

    void dispatch(const json& data, const std::string& raw);

    void enqueue(const std::string& msg);
    void arm_timer();
    void flush();
    void on_write(beast::error_code ec, std::size_t);

    // auth_handlers.cpp
    void handle_register(const json& data, const std::string& raw);
    void handle_login(const json& data, const std::string& raw);

    // room_handlers.cpp
    void handle_create_room(const json& data, const std::string& raw);
    void handle_join_with_code(const json& data, const std::string& raw);
    void handle_join(const json& data, const std::string& raw);
    void handle_get_my_rooms(const json& data, const std::string& raw);
    void handle_rejoin_room(const json& data, const std::string& raw);

    // room_admin_handlers.cpp
    void handle_gen_invite(const json& data, const std::string& raw);
    void handle_rename_room(const json& data, const std::string& raw);
    void handle_get_room_members(const json& data, const std::string& raw);

    // snapshot_handlers.cpp
    void handle_save_snapshot(const json& data, const std::string& raw);
    void handle_get_saves(const json& data, const std::string& raw);
    void handle_load_save(const json& data, const std::string& raw);
    void handle_delete_save(const json& data, const std::string& raw);
    void handle_submit_auto_snapshot(const json& data, const std::string& raw);

    // message_handlers.cpp
    void handle_cursor_or_presence(const json& data, const std::string& raw);
    void handle_default_doc_event(const json& data, const std::string& raw);

    static const HandlerTable& pre_join_table();
    static const HandlerTable& post_join_table();

    websocket::stream<beast::tcp_stream> ws_;
    beast::flat_buffer buffer_;

    Server& server_;
    std::shared_ptr<Room> room_;
    uint32_t site_id_ = 0;
    bool joined_ = false;
    std::string username_;

    std::vector<std::string> pending_;
    bool is_writing_ = false;
    bool timer_armed_ = false;
    net::steady_timer batch_timer_;
    std::string write_buf_;
};
