#include "database.h"

#include <cstdlib>
#include <iostream>
#include <random>

Database::Database() {
    open_and_init();
    prepare_statements();
    thread_ = std::thread(&Database::worker_loop, this);
}

Database::~Database() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        stop_ = true;
    }
    cv_.notify_all();
    if (thread_.joinable()) thread_.join();

    sqlite3_finalize(stmt_insert_event_);
    sqlite3_finalize(stmt_insert_user_);
    sqlite3_finalize(stmt_login_);
    sqlite3_finalize(stmt_check_code_exists_);
    sqlite3_finalize(stmt_insert_invite_);
    sqlite3_finalize(stmt_join_with_code_);
    sqlite3_finalize(stmt_use_code_);
    sqlite3_finalize(stmt_insert_member_);
    sqlite3_finalize(stmt_get_room_name_);
    sqlite3_finalize(stmt_check_member_);
    sqlite3_finalize(stmt_get_owner_);
    sqlite3_finalize(stmt_update_room_name_);
    sqlite3_finalize(stmt_get_members_);
    sqlite3_finalize(stmt_get_my_rooms_);
    sqlite3_finalize(stmt_get_history_);
    sqlite3_finalize(stmt_clear_events_);
    sqlite3_finalize(stmt_delete_quick_save_);
    sqlite3_finalize(stmt_get_saves_);
    sqlite3_finalize(stmt_delete_save_);
    sqlite3_finalize(stmt_get_save_by_id_);
    sqlite3_finalize(stmt_get_latest_auto_snap_);
    sqlite3_finalize(stmt_get_events_after_rowid_);
    sqlite3_finalize(stmt_insert_auto_snap_);
    sqlite3_finalize(stmt_delete_old_auto_snaps_);
    sqlite3_finalize(stmt_get_event_count_);

    sqlite3_close(db_);
}

void Database::open_and_init() {
    if (sqlite3_open("collab_doc_v2.db", &db_)) {
        std::cerr << "Failed to open database!" << std::endl;
        std::exit(1);
    }
    sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "PRAGMA synchronous=NORMAL;", nullptr, nullptr, nullptr);

    sqlite3_exec(db_,
        "CREATE TABLE IF NOT EXISTS events ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, doc_id TEXT, payload TEXT);",
        nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "CREATE INDEX IF NOT EXISTS idx_events_doc_id ON events(doc_id);", nullptr, nullptr, nullptr);

    char* errMsgUser = nullptr;
    if (sqlite3_exec(db_,
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "username TEXT UNIQUE NOT NULL, "
        "password TEXT NOT NULL);",
        nullptr, nullptr, &errMsgUser) != SQLITE_OK) {
        std::cerr << "Failed to create users table" << std::endl;
        sqlite3_free(errMsgUser);
    } else {
        std::cout << "Account Database Ready!" << std::endl;
    }

    sqlite3_exec(db_,
        "CREATE TABLE IF NOT EXISTS invite_codes ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "code TEXT UNIQUE NOT NULL, "
        "doc_id TEXT NOT NULL, "
        "room_name TEXT NOT NULL DEFAULT '', "
        "created_by TEXT NOT NULL, "
        "used INTEGER DEFAULT 0, "
        "max_uses INTEGER DEFAULT 1, "
        "expires_at INTEGER DEFAULT NULL);",
        nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "CREATE INDEX IF NOT EXISTS idx_invite_codes_doc_id ON invite_codes(doc_id);", nullptr, nullptr, nullptr);
    sqlite3_exec(db_,
        "ALTER TABLE invite_codes ADD COLUMN created_at INTEGER DEFAULT (strftime('%s','now'));",
        nullptr, nullptr, nullptr);

    sqlite3_exec(db_,
        "CREATE TABLE IF NOT EXISTS room_members ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "username TEXT NOT NULL, "
        "doc_id TEXT NOT NULL, "
        "joined_at INTEGER NOT NULL DEFAULT (strftime('%s','now')), "
        "UNIQUE(username, doc_id));",
        nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "CREATE INDEX IF NOT EXISTS idx_room_members_username ON room_members(username);", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "CREATE INDEX IF NOT EXISTS idx_room_members_doc_id ON room_members(doc_id);", nullptr, nullptr, nullptr);

    sqlite3_exec(db_,
        "CREATE TABLE IF NOT EXISTS saves ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "doc_id TEXT NOT NULL, "
        "created_by TEXT NOT NULL, "
        "name TEXT NOT NULL, "
        "is_quick INTEGER DEFAULT 0, "
        "created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')), "
        "doc_state TEXT NOT NULL, "
        "shapes TEXT NOT NULL);",
        nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "ALTER TABLE saves ADD COLUMN is_auto INTEGER DEFAULT 0;", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "CREATE INDEX IF NOT EXISTS idx_saves_doc_id ON saves(doc_id);", nullptr, nullptr, nullptr);
}

void Database::prepare_statements() {
    sqlite3_prepare_v2(db_, "INSERT INTO events (doc_id, payload) VALUES (?, ?);", -1, &stmt_insert_event_, nullptr);
    sqlite3_prepare_v2(db_, "INSERT INTO users (username, password) VALUES (?, ?);", -1, &stmt_insert_user_, nullptr);
    sqlite3_prepare_v2(db_, "SELECT id FROM users WHERE username = ? AND password = ?;", -1, &stmt_login_, nullptr);
    sqlite3_prepare_v2(db_, "SELECT id FROM invite_codes WHERE code=?;", -1, &stmt_check_code_exists_, nullptr);
    sqlite3_prepare_v2(db_,
        "INSERT INTO invite_codes (code, doc_id, room_name, created_by, max_uses, expires_at) VALUES (?,?,?,?,?,?);",
        -1, &stmt_insert_invite_, nullptr);
    sqlite3_prepare_v2(db_,
        "SELECT doc_id, room_name, max_uses, expires_at FROM invite_codes WHERE code=? AND (max_uses=-1 OR used=0);",
        -1, &stmt_join_with_code_, nullptr);
    sqlite3_prepare_v2(db_, "UPDATE invite_codes SET used=1 WHERE code=?;", -1, &stmt_use_code_, nullptr);
    sqlite3_prepare_v2(db_,
        "INSERT OR IGNORE INTO room_members (username, doc_id) VALUES (?, ?);",
        -1, &stmt_insert_member_, nullptr);
    sqlite3_prepare_v2(db_,
        "SELECT room_name FROM invite_codes WHERE doc_id=? LIMIT 1;",
        -1, &stmt_get_room_name_, nullptr);
    sqlite3_prepare_v2(db_,
        "SELECT id FROM room_members WHERE username=? AND doc_id=?;",
        -1, &stmt_check_member_, nullptr);
    sqlite3_prepare_v2(db_,
        "SELECT created_by FROM invite_codes WHERE doc_id=? LIMIT 1;",
        -1, &stmt_get_owner_, nullptr);
    sqlite3_prepare_v2(db_,
        "UPDATE invite_codes SET room_name=? WHERE doc_id=?;",
        -1, &stmt_update_room_name_, nullptr);
    sqlite3_prepare_v2(db_,
        "SELECT username FROM room_members WHERE doc_id=? ORDER BY joined_at ASC;",
        -1, &stmt_get_members_, nullptr);
    sqlite3_prepare_v2(db_,
        "SELECT rm.doc_id, "
        "       COALESCE(MAX(ic.room_name), rm.doc_id) AS room_name, "
        "       COALESCE(MAX(ic.created_by), '') AS created_by, "
        "       COALESCE(MAX(ic.created_at), 0) AS created_at, "
        "       rm.joined_at "
        "FROM room_members rm "
        "LEFT JOIN invite_codes ic ON ic.doc_id = rm.doc_id "
        "WHERE rm.username = ? "
        "GROUP BY rm.doc_id "
        "ORDER BY rm.joined_at DESC;",
        -1, &stmt_get_my_rooms_, nullptr);
    sqlite3_prepare_v2(db_,
        "SELECT payload FROM events WHERE doc_id = ? ORDER BY id ASC;",
        -1, &stmt_get_history_, nullptr);
    sqlite3_prepare_v2(db_, "DELETE FROM events WHERE doc_id=?;", -1, &stmt_clear_events_, nullptr);

    sqlite3_prepare_v2(db_,
        "INSERT INTO saves (doc_id, created_by, name, is_quick, doc_state, shapes) VALUES (?,?,?,?,?,?);",
        -1, &stmt_insert_save_, nullptr);
    sqlite3_prepare_v2(db_,
        "DELETE FROM saves WHERE doc_id=? AND is_quick=1;",
        -1, &stmt_delete_quick_save_, nullptr);
    sqlite3_prepare_v2(db_,
        "SELECT id, created_by, name, is_quick, created_at FROM saves WHERE doc_id=? ORDER BY is_quick DESC, created_at DESC;",
        -1, &stmt_get_saves_, nullptr);
    sqlite3_prepare_v2(db_,
        "DELETE FROM saves WHERE id=? AND doc_id=?;",
        -1, &stmt_delete_save_, nullptr);
    sqlite3_prepare_v2(db_,
        "SELECT name, doc_state, shapes FROM saves WHERE id=? AND doc_id=?;",
        -1, &stmt_get_save_by_id_, nullptr);

    sqlite3_prepare_v2(db_,
        "SELECT id, doc_state, shapes FROM saves WHERE doc_id=? AND is_auto=1 ORDER BY id DESC LIMIT 1;",
        -1, &stmt_get_latest_auto_snap_, nullptr);
    sqlite3_prepare_v2(db_,
        "SELECT payload FROM events WHERE doc_id=? AND id>? ORDER BY id ASC;",
        -1, &stmt_get_events_after_rowid_, nullptr);
    sqlite3_prepare_v2(db_,
        "INSERT INTO saves (doc_id, created_by, name, is_quick, is_auto, doc_state, shapes) VALUES (?,?,?,0,1,?,?);",
        -1, &stmt_insert_auto_snap_, nullptr);
    sqlite3_prepare_v2(db_,
        "DELETE FROM saves WHERE doc_id=? AND is_auto=1 AND id < (SELECT MAX(id) FROM saves WHERE doc_id=? AND is_auto=1);",
        -1, &stmt_delete_old_auto_snaps_, nullptr);
    sqlite3_prepare_v2(db_,
        "SELECT COUNT(*) FROM events WHERE doc_id=?;",
        -1, &stmt_get_event_count_, nullptr);
}

void Database::worker_loop() {
    while (true) {
        std::function<void()> task;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            cv_.wait(lock, [this] { return !queue_.empty() || stop_; });
            if (stop_ && queue_.empty()) break;
            task = std::move(queue_.front());
            queue_.pop();
        }
        task();
    }
}

void Database::post_task(std::function<void()> task) {
    std::lock_guard<std::mutex> lock(mutex_);
    queue_.push(std::move(task));
    cv_.notify_one();
}

void Database::push_event(const std::string& doc_id, const std::string& payload) {
    post_task([this, doc_id, payload]() {
        sqlite3_reset(stmt_insert_event_);
        sqlite3_bind_text(stmt_insert_event_, 1, doc_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt_insert_event_, 2, payload.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt_insert_event_);
    });
}

std::string Database::generate_unique_code() {
    static const char chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    static std::mt19937 rng(std::random_device{}());
    static std::uniform_int_distribution<int> dist(0, 35);
    std::string code;
    while (true) {
        code.assign(6, ' ');
        for (auto& c : code) c = chars[dist(rng)];
        sqlite3_reset(stmt_check_code_exists_);
        sqlite3_bind_text(stmt_check_code_exists_, 1, code.c_str(), -1, SQLITE_TRANSIENT);
        bool exists = (sqlite3_step(stmt_check_code_exists_) == SQLITE_ROW);
        if (!exists) break;
    }
    return code;
}

void Database::insert_invite(const std::string& code, const std::string& doc_id,
                             const std::string& room_name, const std::string& created_by,
                             int max_uses, int64_t expires_at) {
    sqlite3_reset(stmt_insert_invite_);
    sqlite3_bind_text(stmt_insert_invite_, 1, code.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt_insert_invite_, 2, doc_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt_insert_invite_, 3, room_name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt_insert_invite_, 4, created_by.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt_insert_invite_, 5, max_uses);
    if (expires_at > 0) sqlite3_bind_int64(stmt_insert_invite_, 6, expires_at);
    else sqlite3_bind_null(stmt_insert_invite_, 6);
    sqlite3_step(stmt_insert_invite_);
}

bool Database::check_is_owner(const std::string& doc_id, const std::string& uname) {
    sqlite3_reset(stmt_get_owner_);
    sqlite3_bind_text(stmt_get_owner_, 1, doc_id.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt_get_owner_) == SQLITE_ROW) {
        std::string creator = reinterpret_cast<const char*>(sqlite3_column_text(stmt_get_owner_, 0));
        return creator == uname;
    }
    return false;
}

std::string Database::query_room_name(const std::string& doc_id) {
    std::string room_name;
    sqlite3_reset(stmt_get_room_name_);
    sqlite3_bind_text(stmt_get_room_name_, 1, doc_id.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt_get_room_name_) == SQLITE_ROW)
        room_name = reinterpret_cast<const char*>(sqlite3_column_text(stmt_get_room_name_, 0));
    return room_name;
}
