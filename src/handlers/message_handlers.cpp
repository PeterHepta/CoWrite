#include "../net/session.h"
#include "../core/room.h"

void Session::handle_cursor_or_presence(const json& /*data*/, const std::string& raw) {
    if (room_) room_->broadcast_except(this, raw);
}

void Session::handle_default_doc_event(const json& /*data*/, const std::string& raw) {
    if (!room_) return;
    room_->save_event(raw);
    room_->broadcast_except(this, raw);
}
