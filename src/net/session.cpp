#include "session.h"
#include "../core/server.h"
#include "../core/room.h"

#include <iostream>

Session::Session(tcp::socket&& socket, Server& server)
    : ws_(std::move(socket)),
      server_(server),
      batch_timer_(ws_.get_executor()) {}

Session::~Session() {
    if (!username_.empty()) server_.unregister_user(username_, this);
    if (room_) room_->leave(this);
}

void Session::run() {
    net::dispatch(ws_.get_executor(),
                  beast::bind_front_handler(&Session::on_run, shared_from_this()));
}

void Session::on_run() {
    ws_.async_accept(beast::bind_front_handler(&Session::on_accept, shared_from_this()));
}

void Session::on_accept(beast::error_code ec) {
    if (!ec) do_read();
}

void Session::do_read() {
    ws_.async_read(buffer_,
                   beast::bind_front_handler(&Session::on_read, shared_from_this()));
}

void Session::on_read(beast::error_code ec, std::size_t /*bytes*/) {
    if (ec) return;
    std::string payload = beast::buffers_to_string(buffer_.data());
    buffer_.consume(buffer_.size());

    try {
        json data = json::parse(payload);
        dispatch(data, payload);
    } catch (...) {}

    do_read();
}

void Session::dispatch(const json& data, const std::string& raw) {
    const std::string msg_type = data.value("type", "");
    if (!joined_) {
        const auto& table = pre_join_table();
        auto it = table.find(msg_type);
        if (it != table.end()) (this->*(it->second))(data, raw);
        return;
    }
    const auto& table = post_join_table();
    auto it = table.find(msg_type);
    if (it != table.end()) {
        (this->*(it->second))(data, raw);
    } else {
        // 默认：文档事件 —— 持久化 + 广播
        handle_default_doc_event(data, raw);
    }
}

const Session::HandlerTable& Session::pre_join_table() {
    static const HandlerTable t = {
        {"register",       &Session::handle_register},
        {"login",          &Session::handle_login},
        {"create_room",    &Session::handle_create_room},
        {"join_with_code", &Session::handle_join_with_code},
        {"join",           &Session::handle_join},
        {"get_my_rooms",   &Session::handle_get_my_rooms},
        {"rejoin_room",    &Session::handle_rejoin_room},
    };
    return t;
}

const Session::HandlerTable& Session::post_join_table() {
    static const HandlerTable t = {
        {"gen_invite",            &Session::handle_gen_invite},
        {"rename_room",           &Session::handle_rename_room},
        {"get_room_members",      &Session::handle_get_room_members},
        {"save_snapshot",         &Session::handle_save_snapshot},
        {"quicksave_snapshot",    &Session::handle_save_snapshot},
        {"get_saves",             &Session::handle_get_saves},
        {"load_save",             &Session::handle_load_save},
        {"delete_save",           &Session::handle_delete_save},
        {"cursor",                &Session::handle_cursor_or_presence},
        {"presence",              &Session::handle_cursor_or_presence},
        {"submit_auto_snapshot",  &Session::handle_submit_auto_snapshot},
    };
    return t;
}

void Session::send(const std::string& message) {
    net::post(ws_.get_executor(),
              [self = shared_from_this(), message]() { self->enqueue(message); });
}

void Session::send_shared(std::shared_ptr<const std::string> message) {
    net::post(ws_.get_executor(),
              [self = shared_from_this(), message]() { self->enqueue(*message); });
}

void Session::enqueue(const std::string& msg) {
    pending_.push_back(msg);
    if (is_writing_) return;
    if (!timer_armed_) arm_timer();
}

void Session::arm_timer() {
    timer_armed_ = true;
    batch_timer_.expires_after(std::chrono::milliseconds(2));
    batch_timer_.async_wait([self = shared_from_this()](beast::error_code ec) {
        if (ec) return;
        self->timer_armed_ = false;
        if (!self->pending_.empty() && !self->is_writing_)
            self->flush();
    });
}

void Session::flush() {
    if (pending_.size() == 1) {
        write_buf_ = std::move(pending_[0]);
    } else {
        std::string out;
        out.reserve(64 + pending_.size() * 64);
        out += R"({"type":"batch","msgs":[)";
        for (std::size_t i = 0; i < pending_.size(); ++i) {
            if (i) out += ',';
            out += pending_[i];
        }
        out += "]}";
        write_buf_ = std::move(out);
    }
    pending_.clear();
    is_writing_ = true;
    ws_.text(true);
    ws_.async_write(net::buffer(write_buf_),
                    beast::bind_front_handler(&Session::on_write, shared_from_this()));
}

void Session::on_write(beast::error_code ec, std::size_t) {
    if (ec) return;
    is_writing_ = false;
    if (!pending_.empty()) flush();
}
