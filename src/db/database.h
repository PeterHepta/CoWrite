#pragma once

#include <sqlite3.h>

#include <condition_variable>
#include <functional>
#include <mutex>
#include <queue>
#include <string>
#include <thread>

/**
 * @brief 封装 SQLite 连接、所有预编译语句以及串行执行任务的 worker 线程。
 *
 * 所有需要访问数据库的代码必须通过 post_db_task() 将任务投递到 worker
 * 线程，确保 sqlite3 操作串行化、无需对每个 stmt 上锁。
 */
class Database {
public:
    Database();
    ~Database();

    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;

    void post_task(std::function<void()> task);
    void push_event(const std::string& doc_id, const std::string& payload);

    // 以下三个方法只能在 worker 线程内调用（即在 post_task 的 lambda 里）
    std::string generate_unique_code();
    void insert_invite(const std::string& code, const std::string& doc_id,
                       const std::string& room_name, const std::string& created_by,
                       int max_uses, int64_t expires_at);
    bool check_is_owner(const std::string& doc_id, const std::string& uname);
    std::string query_room_name(const std::string& doc_id);

    sqlite3* handle() { return db_; }

    // 预编译语句直接公开 —— handler 在 worker 线程内通过它们拼装 SQL 调用
    sqlite3_stmt* stmt_insert_event_        = nullptr;
    sqlite3_stmt* stmt_insert_user_         = nullptr;
    sqlite3_stmt* stmt_login_               = nullptr;
    sqlite3_stmt* stmt_check_code_exists_   = nullptr;
    sqlite3_stmt* stmt_insert_invite_       = nullptr;
    sqlite3_stmt* stmt_join_with_code_      = nullptr;
    sqlite3_stmt* stmt_use_code_            = nullptr;
    sqlite3_stmt* stmt_insert_member_       = nullptr;
    sqlite3_stmt* stmt_get_room_name_       = nullptr;
    sqlite3_stmt* stmt_check_member_        = nullptr;
    sqlite3_stmt* stmt_get_owner_           = nullptr;
    sqlite3_stmt* stmt_update_room_name_    = nullptr;
    sqlite3_stmt* stmt_get_members_         = nullptr;
    sqlite3_stmt* stmt_get_my_rooms_        = nullptr;
    sqlite3_stmt* stmt_get_history_         = nullptr;
    sqlite3_stmt* stmt_clear_events_        = nullptr;
    sqlite3_stmt* stmt_insert_save_         = nullptr;
    sqlite3_stmt* stmt_delete_quick_save_   = nullptr;
    sqlite3_stmt* stmt_get_saves_           = nullptr;
    sqlite3_stmt* stmt_delete_save_         = nullptr;
    sqlite3_stmt* stmt_get_save_by_id_      = nullptr;
    sqlite3_stmt* stmt_get_latest_auto_snap_    = nullptr;
    sqlite3_stmt* stmt_get_events_after_rowid_  = nullptr;
    sqlite3_stmt* stmt_insert_auto_snap_        = nullptr;
    sqlite3_stmt* stmt_delete_old_auto_snaps_   = nullptr;
    sqlite3_stmt* stmt_get_event_count_         = nullptr;

private:
    void open_and_init();
    void prepare_statements();
    void worker_loop();

    sqlite3* db_ = nullptr;

    std::queue<std::function<void()>> queue_;
    std::mutex mutex_;
    std::condition_variable cv_;
    std::thread thread_;
    bool stop_ = false;
};
