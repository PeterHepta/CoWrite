#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/strand.hpp>
#include <nlohmann/json.hpp>
#include <sqlite3.h>
#include <openssl/sha.h>
#include <iostream>
#include <memory>
#include <string>
#include <sstream>
#include <iomanip>
#include <unordered_set>
#include <unordered_map>
#include <mutex>
#include <queue>
#include <thread>
#include <condition_variable>
#include <random>
#include <chrono>
#include <functional>

/**
 * @brief 计算字符串的 SHA-256 哈希值
 *
 * @param input 待哈希的原始字符串
 * @return 十六进制编码的哈希字符串（64字符）
 */
static std::string sha256(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.size(), hash);
    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    return oss.str();
}

namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;
namespace net = boost::asio;
using tcp = boost::asio::ip::tcp;
using json = nlohmann::json;

class Session;
class Server;

/**
 * @brief 代表一个协作文档房间
 *
 * 管理加入该房间的所有 Session，负责消息广播、
 * 历史事件回放以及将事件持久化到数据库。
 */
class Room {
    std::string doc_id_;
    Server& server_;
    sqlite3* db_;
    std::unordered_set<Session*> sessions_;
    std::mutex mutex_;
    uint32_t next_site_id_ = 1;

public:
    /**
     * @brief 构造 Room 对象
     * @param doc_id 文档唯一标识
     * @param server 所属 Server 引用
     * @param db     SQLite 数据库句柄
     */
    Room(std::string doc_id, Server& server, sqlite3* db)
        : doc_id_(std::move(doc_id)), server_(server), db_(db) {
        std::cout << "[Room] Document " << doc_id_ << " activated in memory." << std::endl;
    }

    /**
     * @brief 将 Session 加入房间
     * @param session 待加入的会话指针
     */
    void join(Session* session);

    /**
     * @brief 将 Session 从房间移除
     * @param session 待移除的会话指针
     */
    void leave(Session* session);

    /**
     * @brief 向除 sender 外的所有成员广播消息
     * @param sender  发送方 Session，不会收到自己的消息
     * @param message 待广播的 JSON 字符串
     */
    void broadcast_except(Session* sender, const std::string& message);

    /**
     * @brief 向房间内所有成员广播消息
     * @param message 待广播的 JSON 字符串
     */
    void broadcast_all(const std::string& message);

    /**
     * @brief 将数据库中的历史事件批量发送给指定 Session
     * @param session 目标会话指针
     */
    void send_history(Session* session);

    /**
     * @brief 将事件异步写入数据库
     * @param payload 事件的 JSON 字符串
     */
    void save_event(const std::string& payload);

    /**
     * @brief 生成并返回下一个唯一的 site_id
     * @return 单调递增的站点 ID
     */
    uint32_t generate_site_id() { return next_site_id_++; }

    /**
     * @brief 获取文档 ID
     * @return doc_id 的常量引用
     */
    const std::string& doc_id() const { return doc_id_; }

    /**
     * @brief 检查指定 Session 是否在本房间内
     * @param session 待检查的会话指针
     * @return true 表示在房间内，false 表示不在
     */
    bool has_session(Session* session) {
        std::lock_guard<std::mutex> lock(mutex_);
        return sessions_.count(session) > 0;
    }
};

/**
 * @brief 全局服务器，管理房间、用户会话及数据库操作
 *
 * 持有 SQLite 连接和所有预编译语句，通过独立的
 * db_thread_ 串行执行数据库任务以避免并发冲突。
 */
class Server {
    std::unordered_map<std::string, std::shared_ptr<Room>> rooms_;
    std::mutex mutex_;

    std::queue<std::function<void()>> db_queue_;
    std::mutex db_mutex_;
    std::condition_variable db_cv_;
    std::thread db_thread_;
    bool stop_db_ = false;

    std::unordered_map<std::string, Session*> active_users_;
    std::mutex user_mutex_;

public:
    sqlite3* db_ = nullptr;

    // 预编译语句缓存
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

    /**
     * @brief 构造 Server，初始化数据库表结构并预编译 SQL 语句，启动 db_thread_
     */
    Server() {
        if (sqlite3_open("collab_doc_v2.db", &db_)) {
            std::cerr << "Failed to open database!" << std::endl; exit(1);
        }
        sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
        sqlite3_exec(db_, "PRAGMA synchronous=NORMAL;", nullptr, nullptr, nullptr);

        const char* sql = "CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, doc_id TEXT, payload TEXT);";
        sqlite3_exec(db_, sql, nullptr, nullptr, nullptr);
        sqlite3_exec(db_, "CREATE INDEX IF NOT EXISTS idx_events_doc_id ON events(doc_id);", nullptr, nullptr, nullptr);

        const char* create_users_table_sql =
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "username TEXT UNIQUE NOT NULL, "
        "password TEXT NOT NULL"
        ");";

        char* errMsgUser = nullptr;
        if (sqlite3_exec(db_, create_users_table_sql, nullptr, nullptr, &errMsgUser) != SQLITE_OK) {
            std::cerr << "Failed to create users table" << std::endl;
            sqlite3_free(errMsgUser);
        } else {
            std::cout << "Account Database Ready!" << std::endl;
        }

        const char* create_invite_codes_sql =
        "CREATE TABLE IF NOT EXISTS invite_codes ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "code TEXT UNIQUE NOT NULL, "
        "doc_id TEXT NOT NULL, "
        "room_name TEXT NOT NULL DEFAULT '', "
        "created_by TEXT NOT NULL, "
        "used INTEGER DEFAULT 0, "
        "max_uses INTEGER DEFAULT 1, "
        "expires_at INTEGER DEFAULT NULL"
        ");";
        sqlite3_exec(db_, create_invite_codes_sql, nullptr, nullptr, nullptr);
        sqlite3_exec(db_, "CREATE INDEX IF NOT EXISTS idx_invite_codes_doc_id ON invite_codes(doc_id);", nullptr, nullptr, nullptr);

        // Migration: add created_at to invite_codes (ignored if already exists)
        sqlite3_exec(db_,
            "ALTER TABLE invite_codes ADD COLUMN created_at INTEGER DEFAULT (strftime('%s','now'));",
            nullptr, nullptr, nullptr);

        const char* create_room_members_sql =
            "CREATE TABLE IF NOT EXISTS room_members ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "username TEXT NOT NULL, "
            "doc_id TEXT NOT NULL, "
            "joined_at INTEGER NOT NULL DEFAULT (strftime('%s','now')), "
            "UNIQUE(username, doc_id)"
            ");";
        sqlite3_exec(db_, create_room_members_sql, nullptr, nullptr, nullptr);
        sqlite3_exec(db_, "CREATE INDEX IF NOT EXISTS idx_room_members_username ON room_members(username);", nullptr, nullptr, nullptr);
        sqlite3_exec(db_, "CREATE INDEX IF NOT EXISTS idx_room_members_doc_id ON room_members(doc_id);", nullptr, nullptr, nullptr);

        // 预编译语句
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
        sqlite3_prepare_v2(db_,
            "DELETE FROM events WHERE doc_id=?;",
            -1, &stmt_clear_events_, nullptr);

        // saves 表
        sqlite3_exec(db_,
            "CREATE TABLE IF NOT EXISTS saves ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "doc_id TEXT NOT NULL, "
            "created_by TEXT NOT NULL, "
            "name TEXT NOT NULL, "
            "is_quick INTEGER DEFAULT 0, "
            "created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')), "
            "doc_state TEXT NOT NULL, "
            "shapes TEXT NOT NULL"
            ");",
            nullptr, nullptr, nullptr);
        sqlite3_exec(db_,
            "CREATE INDEX IF NOT EXISTS idx_saves_doc_id ON saves(doc_id);",
            nullptr, nullptr, nullptr);

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

        db_thread_ = std::thread(&Server::db_worker_loop, this);
    }

    /**
     * @brief 析构 Server，停止 db_thread_，释放所有预编译语句并关闭数据库
     */
    ~Server() {
        {
            std::lock_guard<std::mutex> lock(db_mutex_);
            stop_db_ = true;
        }
        db_cv_.notify_all();
        if (db_thread_.joinable()) db_thread_.join();

        // 释放预编译语句
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

        if (db_) sqlite3_close(db_);
    }

    /**
     * @brief 获取已有 Room，若不存在则创建并缓存
     * @param doc_id 文档唯一标识
     * @return 对应 Room 的 shared_ptr
     */
    std::shared_ptr<Room> get_or_create_room(const std::string& doc_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (rooms_.find(doc_id) == rooms_.end()) {
            rooms_[doc_id] = std::make_shared<Room>(doc_id, *this, db_);
        }
        return rooms_[doc_id];
    }

    /**
     * @brief 将任意可调用对象投递到数据库串行队列
     * @param task 待执行的任务（在 db_thread_ 中运行）
     */
    void post_db_task(std::function<void()> task) {
        std::lock_guard<std::mutex> lock(db_mutex_);
        db_queue_.push(std::move(task));
        db_cv_.notify_one();
    }

    /**
     * @brief 将文档事件异步持久化到数据库
     * @param doc_id  文档唯一标识
     * @param payload 事件的 JSON 字符串
     */
    void push_db_task(const std::string& doc_id, const std::string& payload) {
        post_db_task([this, doc_id, payload]() {
            sqlite3_reset(stmt_insert_event_);
            sqlite3_bind_text(stmt_insert_event_, 1, doc_id.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt_insert_event_, 2, payload.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(stmt_insert_event_);
        });
    }

    /**
     * @brief 注册登录用户与其 Session 的映射；若该用户已在线则踢掉旧连接
     * @param username 登录的用户名
     * @param session  对应的 Session 指针
     */
    void register_user(const std::string& username, Session* session);

    /**
     * @brief 注销用户登录，从在线表中移除对应映射
     * @param username 用户名
     * @param session  对应的 Session 指针（仅当匹配时才移除）
     */
    void unregister_user(const std::string& username, Session* session);

    /**
     * @brief 判断用户当前是否在线
     * @param username 用户名
     * @return true 表示在线
     */
    bool is_user_online(const std::string& username) {
        std::lock_guard<std::mutex> lock(user_mutex_);
        return active_users_.count(username) > 0;
    }

    /**
     * @brief 根据用户名获取其当前 Session 指针
     * @param username 用户名
     * @return Session 指针，若不在线则返回 nullptr
     */
    Session* get_user_session(const std::string& username) {
        std::lock_guard<std::mutex> lock(user_mutex_);
        auto it = active_users_.find(username);
        return it != active_users_.end() ? it->second : nullptr;
    }

    /**
     * @brief 生成一个 6 位随机邀请码（大写字母 + 数字）
     * @return 唯一性需由调用方校验的邀请码字符串
     */
    std::string generate_invite_code() {
        static const char chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        static std::mt19937 rng(std::random_device{}());
        static std::uniform_int_distribution<int> dist(0, 35);
        std::string code(6, ' ');
        for (auto& c : code) c = chars[dist(rng)];
        return code;
    }

    /**
     * @brief 根据用户名和当前时间戳生成唯一的文档 ID
     * @param username 房间创建者的用户名
     * @return 格式为 "username_timestamp" 的文档 ID
     */
    std::string generate_doc_id(const std::string& username) {
        auto ts = std::chrono::steady_clock::now().time_since_epoch().count();
        return username + "_" + std::to_string(ts);
    }

private:
    /**
     * @brief 数据库工作线程主循环，串行消费 db_queue_ 中的任务
     */
    void db_worker_loop() {
        while (true) {
            std::function<void()> task;
            {
                std::unique_lock<std::mutex> lock(db_mutex_);
                db_cv_.wait(lock, [this]{ return !db_queue_.empty() || stop_db_; });
                if (stop_db_ && db_queue_.empty()) break;
                task = std::move(db_queue_.front());
                db_queue_.pop();
            }
            task();
        }
    }
};

void Room::save_event(const std::string& payload) { server_.push_db_task(doc_id_, payload); }

/**
 * @brief 代表一个 WebSocket 客户端连接
 *
 * 每个 Session 对应一条 TCP 连接，负责读取客户端消息、
 * 路由到相应处理逻辑，并通过批量写入（batching）机制
 * 将消息高效地发送回客户端。
 */
class Session : public std::enable_shared_from_this<Session> {
    websocket::stream<beast::tcp_stream> ws_;
    beast::flat_buffer buffer_;
    Server& server_;
    std::shared_ptr<Room> room_;
    uint32_t site_id_ = 0;
    bool joined_ = false;

    // write batching
    std::vector<std::string> pending_; 
    bool is_writing_ = false;
    bool timer_armed_ = false;
    net::steady_timer batch_timer_;
    std::string write_buf_;              // 当前正在发送的帧内容

    std::string username_;

public:
    /**
     * @brief 构造 Session
     * @param socket 已接受的 TCP socket
     * @param server 全局 Server 引用
     */
    Session(tcp::socket&& socket, Server& server)
        : ws_(std::move(socket)), server_(server),
          batch_timer_(ws_.get_executor()) {}

    /**
     * @brief 析构 Session，自动注销用户并离开房间
     */
    ~Session() {
        if (!username_.empty()) server_.unregister_user(username_, this);
        if (room_) room_->leave(this);
    }

    /** @brief 启动会话，将 on_run 派发到 executor */
    void run() { net::dispatch(ws_.get_executor(), beast::bind_front_handler(&Session::on_run, shared_from_this())); }
    /** @brief 发起 WebSocket 握手 */
    void on_run() { ws_.async_accept(beast::bind_front_handler(&Session::on_accept, shared_from_this())); }
    /** @brief 握手完成回调，成功后开始读取 */
    void on_accept(beast::error_code ec) { if (!ec) do_read(); }
    /** @brief 异步读取下一条消息 */
    void do_read() { ws_.async_read(buffer_, beast::bind_front_handler(&Session::on_read, shared_from_this())); }

    /**
     * @brief 读取完成回调，解析 JSON 并路由到对应消息处理逻辑
     * @param ec                错误码
     * @param bytes_transferred 已读取的字节数
     */
    void on_read(beast::error_code ec, std::size_t bytes_transferred) {
        if (ec) return;
        std::string payload = beast::buffers_to_string(buffer_.data());
        buffer_.consume(buffer_.size());

        try {
            json data = json::parse(payload);

            if (!joined_) {
                std::string msg_type = data.value("type", "");

                if (msg_type == "register") {
                    std::string u = data.value("username", "");
                    std::string hashed_p = sha256(data.value("password", ""));
                    auto self = shared_from_this();
                    server_.post_db_task([this, self, u, hashed_p]() {
                        json res = {{"type", "register_res"}};
                        sqlite3_reset(server_.stmt_insert_user_);
                        sqlite3_bind_text(server_.stmt_insert_user_, 1, u.c_str(), -1, SQLITE_TRANSIENT);
                        sqlite3_bind_text(server_.stmt_insert_user_, 2, hashed_p.c_str(), -1, SQLITE_TRANSIENT);
                        if (sqlite3_step(server_.stmt_insert_user_) == SQLITE_DONE) {
                            res["success"] = true; res["msg"] = "Registration successful!";
                        } else {
                            res["success"] = false; res["msg"] = "Registration failed!";
                        }
                        std::string resp = res.dump();
                        net::post(ws_.get_executor(), [self, resp]() { self->send(resp); });
                    });
                }
                else if (msg_type == "login") {
                    std::string u = data.value("username", "");
                    std::string hashed_p = sha256(data.value("password", ""));
                    auto self = shared_from_this();
                    server_.post_db_task([this, self, u, hashed_p]() {
                        bool login_success = false;
                        sqlite3_reset(server_.stmt_login_);
                        sqlite3_bind_text(server_.stmt_login_, 1, u.c_str(), -1, SQLITE_TRANSIENT);
                        sqlite3_bind_text(server_.stmt_login_, 2, hashed_p.c_str(), -1, SQLITE_TRANSIENT);
                        login_success = (sqlite3_step(server_.stmt_login_) == SQLITE_ROW);
                        net::post(ws_.get_executor(), [self, this, u, login_success]() {
                            json res = {{"type", "login_res"}};
                            if (login_success) {
                                username_ = u;
                                server_.register_user(username_, this);
                                res["success"] = true; res["username"] = u; res["msg"] = "Login successful!";
                            } else {
                                res["success"] = false; res["msg"] = "Invalid credentials!";
                            }
                            self->send(res.dump());
                        });
                    });
                }
                else if (msg_type == "create_room") {
                    if (username_.empty()) {
                        send(R"({"type":"create_room_res","success":false,"msg":"请先登录"})");
                    } else {
                        std::string doc_id = server_.generate_doc_id(username_);
                        std::string room_name = data.value("room_name", "未命名房间");
                        std::string invite_type = data.value("invite_type", "once");
                        int max_uses = 1;
                        int64_t expires_at = 0;
                        if (invite_type == "permanent") {
                            max_uses = -1;
                        } else if (invite_type == "timed") {
                            max_uses = -1;
                            int hours = data.value("expire_hours", 24);
                            auto now = std::chrono::system_clock::now().time_since_epoch();
                            expires_at = std::chrono::duration_cast<std::chrono::seconds>(now).count() + hours * 3600;
                        }
                        std::string uname = username_;
                        auto self = shared_from_this();
                        server_.post_db_task([this, self, doc_id, room_name, invite_type, max_uses, expires_at, uname]() {
                            std::string code;
                            while (true) {
                                code = server_.generate_invite_code();
                                sqlite3_reset(server_.stmt_check_code_exists_);
                                sqlite3_bind_text(server_.stmt_check_code_exists_, 1, code.c_str(), -1, SQLITE_TRANSIENT);
                                bool exists = (sqlite3_step(server_.stmt_check_code_exists_) == SQLITE_ROW);
                                if (!exists) break;
                            }
                            sqlite3_reset(server_.stmt_insert_invite_);
                            sqlite3_bind_text(server_.stmt_insert_invite_, 1, code.c_str(), -1, SQLITE_TRANSIENT);
                            sqlite3_bind_text(server_.stmt_insert_invite_, 2, doc_id.c_str(), -1, SQLITE_TRANSIENT);
                            sqlite3_bind_text(server_.stmt_insert_invite_, 3, room_name.c_str(), -1, SQLITE_TRANSIENT);
                            sqlite3_bind_text(server_.stmt_insert_invite_, 4, uname.c_str(), -1, SQLITE_TRANSIENT);
                            sqlite3_bind_int(server_.stmt_insert_invite_, 5, max_uses);
                            if (expires_at > 0) sqlite3_bind_int64(server_.stmt_insert_invite_, 6, expires_at);
                            else sqlite3_bind_null(server_.stmt_insert_invite_, 6);
                            sqlite3_step(server_.stmt_insert_invite_);

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
                }
                else if (msg_type == "join_with_code") {
                    std::string code = data.value("code", "");
                    if (username_.empty()) {
                        send(R"({"type":"join_with_code_res","success":false,"msg":"请先登录"})");
                    } else if (code.empty()) {
                        send(R"({"type":"join_with_code_res","success":false,"msg":"邀请码不能为空"})");
                    } else {
                        std::string uname = username_;
                        auto self = shared_from_this();
                        server_.post_db_task([this, self, code, uname]() {
                            sqlite3_reset(server_.stmt_join_with_code_);
                            sqlite3_bind_text(server_.stmt_join_with_code_, 1, code.c_str(), -1, SQLITE_TRANSIENT);
                            json res = {{"type", "join_with_code_res"}};
                            if (sqlite3_step(server_.stmt_join_with_code_) == SQLITE_ROW) {
                                std::string doc_id = reinterpret_cast<const char*>(sqlite3_column_text(server_.stmt_join_with_code_, 0));
                                std::string room_name = reinterpret_cast<const char*>(sqlite3_column_text(server_.stmt_join_with_code_, 1));
                                int max_uses = sqlite3_column_int(server_.stmt_join_with_code_, 2);
                                bool has_expiry = (sqlite3_column_type(server_.stmt_join_with_code_, 3) != SQLITE_NULL);
                                int64_t expires_at = has_expiry ? sqlite3_column_int64(server_.stmt_join_with_code_, 3) : 0;

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
                                    sqlite3_reset(server_.stmt_use_code_);
                                    sqlite3_bind_text(server_.stmt_use_code_, 1, code.c_str(), -1, SQLITE_TRANSIENT);
                                    sqlite3_step(server_.stmt_use_code_);
                                }
                                res["success"] = true; res["doc_id"] = doc_id; res["room_name"] = room_name;
                                std::cout << "🔓 用户 " << uname << " 使用邀请码 " << code << " 加入房间 " << doc_id << std::endl;
                            } else {
                                res["success"] = false; res["msg"] = "邀请码无效或已被使用";
                            }
                            std::string resp = res.dump();
                            net::post(ws_.get_executor(), [self, resp]() { self->send(resp); });
                        });
                    }
                }
                else if (msg_type == "join") {
                    std::string doc_id = data.value("doc_id", "public_room");
                    room_ = server_.get_or_create_room(doc_id);
                    int req_site = data.value("requested_site_id", 0);
                    if (req_site > 0) site_id_ = req_site; else site_id_ = room_->generate_site_id();

                    room_->join(this);
                    joined_ = true;

                    std::string uname = username_;
                    uint32_t sid = site_id_;
                    auto self = shared_from_this();
                    auto room_ref = room_;
                    server_.post_db_task([this, self, room_ref, doc_id, uname, sid]() {
                        // 记录成员关系
                        sqlite3_reset(server_.stmt_insert_member_);
                        sqlite3_bind_text(server_.stmt_insert_member_, 1, uname.c_str(), -1, SQLITE_TRANSIENT);
                        sqlite3_bind_text(server_.stmt_insert_member_, 2, doc_id.c_str(), -1, SQLITE_TRANSIENT);
                        sqlite3_step(server_.stmt_insert_member_);

                        // 查出房间名
                        std::string room_name;
                        sqlite3_reset(server_.stmt_get_room_name_);
                        sqlite3_bind_text(server_.stmt_get_room_name_, 1, doc_id.c_str(), -1, SQLITE_TRANSIENT);
                        if (sqlite3_step(server_.stmt_get_room_name_) == SQLITE_ROW)
                            room_name = reinterpret_cast<const char*>(sqlite3_column_text(server_.stmt_get_room_name_, 0));

                        net::post(ws_.get_executor(), [self, this, room_ref, room_name, sid, uname]() {
                            json init_msg = {{"type", "init"}, {"site_id", sid}, {"room_name", room_name}};
                            self->send(init_msg.dump());
                            room_ref->send_history(this);
                            json presence_msg = {{"type", "presence"}, {"action", "join"}, {"site_id", sid}, {"username", uname}};
                            room_ref->broadcast_except(this, presence_msg.dump());
                        });
                    });
                }
                else if (msg_type == "get_my_rooms") {
                    if (username_.empty()) {
                        send(R"({"type":"get_my_rooms_res","success":false,"msg":"请先登录"})");
                    } else {
                        std::string uname = username_;
                        auto self = shared_from_this();
                        server_.post_db_task([this, self, uname]() {
                            std::string resp;
                            sqlite3_reset(server_.stmt_get_my_rooms_);
                            sqlite3_bind_text(server_.stmt_get_my_rooms_, 1, uname.c_str(), -1, SQLITE_TRANSIENT);
                            json rooms = json::array();
                            while (sqlite3_step(server_.stmt_get_my_rooms_) == SQLITE_ROW) {
                                json r;
                                auto col_text = [&](int col) -> std::string {
                                    const char* t = reinterpret_cast<const char*>(sqlite3_column_text(server_.stmt_get_my_rooms_, col));
                                    return t ? t : "";
                                };
                                r["doc_id"]     = col_text(0);
                                r["room_name"]  = col_text(1);
                                r["created_by"] = col_text(2);
                                r["created_at"] = sqlite3_column_int64(server_.stmt_get_my_rooms_, 3);
                                r["joined_at"]  = sqlite3_column_int64(server_.stmt_get_my_rooms_, 4);
                                rooms.push_back(r);
                            }
                            resp = json{{"type", "get_my_rooms_res"}, {"success", true}, {"rooms", rooms}}.dump();
                            net::post(ws_.get_executor(), [self, resp]() { self->send(resp); });
                        });
                    }
                }
                else if (msg_type == "rejoin_room") {
                    std::string doc_id = data.value("doc_id", "");
                    if (username_.empty()) {
                        send(R"({"type":"rejoin_room_res","success":false,"msg":"请先登录"})");
                    } else if (doc_id.empty()) {
                        send(R"({"type":"rejoin_room_res","success":false,"msg":"doc_id 不能为空"})");
                    } else {
                        std::string uname = username_;
                        int req_site = data.value("requested_site_id", 0);
                        auto self = shared_from_this();
                        server_.post_db_task([this, self, doc_id, uname, req_site]() {
                            sqlite3_reset(server_.stmt_check_member_);
                            sqlite3_bind_text(server_.stmt_check_member_, 1, uname.c_str(), -1, SQLITE_TRANSIENT);
                            sqlite3_bind_text(server_.stmt_check_member_, 2, doc_id.c_str(), -1, SQLITE_TRANSIENT);
                            bool is_member = (sqlite3_step(server_.stmt_check_member_) == SQLITE_ROW);

                            if (!is_member) {
                                net::post(ws_.get_executor(), [self]() {
                                    self->send(R"({"type":"rejoin_room_res","success":false,"msg":"您没有该房间的访问权限"})");
                                });
                                return;
                            }

                            // 查房间名
                            std::string room_name;
                            sqlite3_reset(server_.stmt_get_room_name_);
                            sqlite3_bind_text(server_.stmt_get_room_name_, 1, doc_id.c_str(), -1, SQLITE_TRANSIENT);
                            if (sqlite3_step(server_.stmt_get_room_name_) == SQLITE_ROW)
                                room_name = reinterpret_cast<const char*>(sqlite3_column_text(server_.stmt_get_room_name_, 0));

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
                }
            } else {
                std::string msg_type = data.value("type", "");
                if (msg_type == "gen_invite") {
                    std::string invite_type = data.value("invite_type", "once");
                    int max_uses = 1;
                    int64_t expires_at = 0;
                    if (invite_type == "permanent") {
                        max_uses = -1;
                    } else if (invite_type == "timed") {
                        max_uses = -1;
                        int hours = data.value("expire_hours", 24);
                        auto now = std::chrono::system_clock::now().time_since_epoch();
                        expires_at = std::chrono::duration_cast<std::chrono::seconds>(now).count() + hours * 3600;
                    }
                    std::string uname = username_;
                    std::string doc_id = room_->doc_id();
                    auto self = shared_from_this();
                    server_.post_db_task([this, self, uname, doc_id, invite_type, max_uses, expires_at]() {
                        // 验证创建者
                        sqlite3_reset(server_.stmt_get_owner_);
                        sqlite3_bind_text(server_.stmt_get_owner_, 1, doc_id.c_str(), -1, SQLITE_TRANSIENT);
                        bool is_owner = false;
                        if (sqlite3_step(server_.stmt_get_owner_) == SQLITE_ROW) {
                            std::string creator = reinterpret_cast<const char*>(sqlite3_column_text(server_.stmt_get_owner_, 0));
                            is_owner = (creator == uname);
                        }

                        if (!is_owner) {
                            net::post(ws_.get_executor(), [self]() {
                                self->send(R"({"type":"gen_invite_res","success":false,"msg":"只有房间创建者才能生成邀请码"})");
                            });
                            return;
                        }

                        // 生成唯一码
                        std::string code;
                        while (true) {
                            code = server_.generate_invite_code();
                            sqlite3_reset(server_.stmt_check_code_exists_);
                            sqlite3_bind_text(server_.stmt_check_code_exists_, 1, code.c_str(), -1, SQLITE_TRANSIENT);
                            bool exists = (sqlite3_step(server_.stmt_check_code_exists_) == SQLITE_ROW);
                            if (!exists) break;
                        }
                        std::string room_name = "未命名房间";
                        sqlite3_reset(server_.stmt_get_room_name_);
                        sqlite3_bind_text(server_.stmt_get_room_name_, 1, doc_id.c_str(), -1, SQLITE_TRANSIENT);
                        if (sqlite3_step(server_.stmt_get_room_name_) == SQLITE_ROW)
                            room_name = reinterpret_cast<const char*>(sqlite3_column_text(server_.stmt_get_room_name_, 0));

                        sqlite3_reset(server_.stmt_insert_invite_);
                        sqlite3_bind_text(server_.stmt_insert_invite_, 1, code.c_str(), -1, SQLITE_TRANSIENT);
                        sqlite3_bind_text(server_.stmt_insert_invite_, 2, doc_id.c_str(), -1, SQLITE_TRANSIENT);
                        sqlite3_bind_text(server_.stmt_insert_invite_, 3, room_name.c_str(), -1, SQLITE_TRANSIENT);
                        sqlite3_bind_text(server_.stmt_insert_invite_, 4, uname.c_str(), -1, SQLITE_TRANSIENT);
                        sqlite3_bind_int(server_.stmt_insert_invite_, 5, max_uses);
                        if (expires_at > 0) sqlite3_bind_int64(server_.stmt_insert_invite_, 6, expires_at);
                        else sqlite3_bind_null(server_.stmt_insert_invite_, 6);
                        sqlite3_step(server_.stmt_insert_invite_);

                        json res = {{"type", "gen_invite_res"}, {"success", true},
                                    {"code", code}, {"invite_type", invite_type}};
                        if (expires_at > 0) res["expires_at"] = expires_at;
                        std::string resp = res.dump();
                        std::cout << "用户 " << uname << " 在房间 " << doc_id
                                  << " 生成新邀请码: " << code << " [" << invite_type << "]" << std::endl;
                        net::post(ws_.get_executor(), [self, resp]() { self->send(resp); });
                    });
                } else if (msg_type == "rename_room") {
                    std::string new_name = data.value("room_name", "");
                    if (new_name.empty()) {
                        send(R"({"type":"rename_room_res","success":false,"msg":"房间名不能为空"})");
                    } else {
                        std::string uname = username_;
                        std::string doc_id = room_->doc_id();
                        auto self = shared_from_this();
                        server_.post_db_task([this, self, uname, doc_id, new_name]() {
                            sqlite3_reset(server_.stmt_get_owner_);
                            sqlite3_bind_text(server_.stmt_get_owner_, 1, doc_id.c_str(), -1, SQLITE_TRANSIENT);
                            bool is_owner = false;
                            if (sqlite3_step(server_.stmt_get_owner_) == SQLITE_ROW) {
                                std::string creator = reinterpret_cast<const char*>(sqlite3_column_text(server_.stmt_get_owner_, 0));
                                is_owner = (creator == uname);
                            }

                            if (!is_owner) {
                                net::post(ws_.get_executor(), [self]() {
                                    self->send(R"({"type":"rename_room_res","success":false,"msg":"只有房间创建者才能修改房间名"})");
                                });
                                return;
                            }
                            sqlite3_reset(server_.stmt_update_room_name_);
                            sqlite3_bind_text(server_.stmt_update_room_name_, 1, new_name.c_str(), -1, SQLITE_TRANSIENT);
                            sqlite3_bind_text(server_.stmt_update_room_name_, 2, doc_id.c_str(), -1, SQLITE_TRANSIENT);
                            sqlite3_step(server_.stmt_update_room_name_);

                            json res = {{"type", "rename_room_res"}, {"success", true}, {"room_name", new_name}};
                            std::string resp = res.dump();
                            std::cout << "用户 " << uname << " 将房间 " << doc_id
                                      << " 重命名为: " << new_name << std::endl;
                            net::post(ws_.get_executor(), [self, resp]() { self->send(resp); });
                        });
                    }
                } else if (msg_type == "get_room_members") {
                    std::string doc_id = room_->doc_id();
                    auto self = shared_from_this();
                    server_.post_db_task([this, self, doc_id]() {
                        std::string room_owner;
                        {
                            sqlite3_reset(server_.stmt_get_owner_);
                            sqlite3_bind_text(server_.stmt_get_owner_, 1, doc_id.c_str(), -1, SQLITE_TRANSIENT);
                            if (sqlite3_step(server_.stmt_get_owner_) == SQLITE_ROW)
                                room_owner = reinterpret_cast<const char*>(sqlite3_column_text(server_.stmt_get_owner_, 0));
                        }
                        sqlite3_reset(server_.stmt_get_members_);
                        sqlite3_bind_text(server_.stmt_get_members_, 1, doc_id.c_str(), -1, SQLITE_TRANSIENT);
                        // 收集用户名列表，回到 io 线程再查在线状态
                        std::vector<std::string> unames;
                        while (sqlite3_step(server_.stmt_get_members_) == SQLITE_ROW)
                            unames.push_back(reinterpret_cast<const char*>(sqlite3_column_text(server_.stmt_get_members_, 0)));

                        net::post(ws_.get_executor(), [self, this, unames, room_owner]() {
                            json members = json::array();
                            for (const auto& uname : unames) {
                                json m;
                                m["username"] = uname;
                                m["is_owner"] = (uname == room_owner);
                                Session* user_session = server_.get_user_session(uname);
                                if (user_session && room_->has_session(user_session)) {
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
                } else if (msg_type == "save_snapshot" || msg_type == "quicksave_snapshot") {
                    bool is_quick = (msg_type == "quicksave_snapshot");
                    std::string save_name = is_quick ? "快速存档" : data.value("name", "默认存档");
                    std::string doc_state = data.value("doc_state", "[]");
                    std::string shapes_str = data.value("shapes", "[]");
                    std::string uname = username_;
                    std::string doc_id = room_->doc_id();
                    auto self = shared_from_this();
                    server_.post_db_task([this, self, is_quick, save_name, doc_state, shapes_str, uname, doc_id]() {
                        if (is_quick) {
                            sqlite3_reset(server_.stmt_delete_quick_save_);
                            sqlite3_bind_text(server_.stmt_delete_quick_save_, 1, doc_id.c_str(), -1, SQLITE_TRANSIENT);
                            sqlite3_step(server_.stmt_delete_quick_save_);
                        }
                        sqlite3_reset(server_.stmt_insert_save_);
                        sqlite3_bind_text(server_.stmt_insert_save_, 1, doc_id.c_str(), -1, SQLITE_TRANSIENT);
                        sqlite3_bind_text(server_.stmt_insert_save_, 2, uname.c_str(), -1, SQLITE_TRANSIENT);
                        sqlite3_bind_text(server_.stmt_insert_save_, 3, save_name.c_str(), -1, SQLITE_TRANSIENT);
                        sqlite3_bind_int(server_.stmt_insert_save_,  4, is_quick ? 1 : 0);
                        sqlite3_bind_text(server_.stmt_insert_save_, 5, doc_state.c_str(), -1, SQLITE_TRANSIENT);
                        sqlite3_bind_text(server_.stmt_insert_save_, 6, shapes_str.c_str(), -1, SQLITE_TRANSIENT);
                        sqlite3_step(server_.stmt_insert_save_);
                        int64_t new_id = sqlite3_last_insert_rowid(server_.db_);
                        auto now = std::chrono::system_clock::now().time_since_epoch();
                        int64_t ts = std::chrono::duration_cast<std::chrono::seconds>(now).count();
                        json res = {{"type","save_snapshot_res"},{"success",true},
                                    {"id",new_id},{"name",save_name},
                                    {"created_at",ts},{"is_quick",is_quick}};
                        std::string resp = res.dump();
                        net::post(ws_.get_executor(), [self, resp]() { self->send(resp); });
                    });
                } else if (msg_type == "get_saves") {
                    std::string doc_id = room_->doc_id();
                    auto self = shared_from_this();
                    server_.post_db_task([this, self, doc_id]() {
                        sqlite3_reset(server_.stmt_get_saves_);
                        sqlite3_bind_text(server_.stmt_get_saves_, 1, doc_id.c_str(), -1, SQLITE_TRANSIENT);
                        json saves = json::array();
                        while (sqlite3_step(server_.stmt_get_saves_) == SQLITE_ROW) {
                            auto col_text = [&](int col) -> std::string {
                                const char* t = reinterpret_cast<const char*>(sqlite3_column_text(server_.stmt_get_saves_, col));
                                return t ? t : "";
                            };
                            json s;
                            s["id"]         = sqlite3_column_int64(server_.stmt_get_saves_, 0);
                            s["created_by"] = col_text(1);
                            s["name"]       = col_text(2);
                            s["is_quick"]   = (sqlite3_column_int(server_.stmt_get_saves_, 3) == 1);
                            s["created_at"] = sqlite3_column_int64(server_.stmt_get_saves_, 4);
                            saves.push_back(s);
                        }
                        json res = {{"type","get_saves_res"},{"success",true},{"saves",saves}};
                        std::string resp = res.dump();
                        net::post(ws_.get_executor(), [self, resp]() { self->send(resp); });
                    });
                } else if (msg_type == "load_save") {
                    int64_t save_id = data.value("save_id", (int64_t)0);
                    std::string doc_id = room_->doc_id();
                    std::string uname = username_;
                    auto self = shared_from_this();
                    auto room_ref = room_;
                    server_.post_db_task([this, self, room_ref, save_id, doc_id, uname]() {
                        sqlite3_reset(server_.stmt_get_save_by_id_);
                        sqlite3_bind_int64(server_.stmt_get_save_by_id_, 1, save_id);
                        sqlite3_bind_text(server_.stmt_get_save_by_id_, 2, doc_id.c_str(), -1, SQLITE_TRANSIENT);
                        if (sqlite3_step(server_.stmt_get_save_by_id_) != SQLITE_ROW) {
                            net::post(ws_.get_executor(), [self]() {
                                self->send(R"({"type":"load_save_res","success":false,"msg":"存档不存在"})");
                            });
                            return;
                        }
                        auto col_text = [&](int col) -> std::string {
                            const char* t = reinterpret_cast<const char*>(sqlite3_column_text(server_.stmt_get_save_by_id_, col));
                            return t ? t : "";
                        };
                        std::string save_name = col_text(0);
                        std::string doc_state_str = col_text(1);
                        std::string shapes_str = col_text(2);

                        // 解析存档内容
                        json doc_state_json = json::array();
                        json shapes_json = json::array();
                        try { doc_state_json = json::parse(doc_state_str); } catch(...) {}
                        try { shapes_json = json::parse(shapes_str); } catch(...) {}

                        // 1. 清空旧 events
                        sqlite3_reset(server_.stmt_clear_events_);
                        sqlite3_bind_text(server_.stmt_clear_events_, 1, doc_id.c_str(), -1, SQLITE_TRANSIENT);
                        sqlite3_step(server_.stmt_clear_events_);

                        // 2. 将 doc_state 每个元素写为 insert 事件
                        for (const auto& item : doc_state_json) {
                            try {
                                json ev = {{"type","insert"},
                                           {"id", item.at("id")},
                                           {"char", item.at("char")},
                                           {"attributes", item.value("attributes", json::object())}};
                                std::string payload = ev.dump();
                                sqlite3_reset(server_.stmt_insert_event_);
                                sqlite3_bind_text(server_.stmt_insert_event_, 1, doc_id.c_str(), -1, SQLITE_TRANSIENT);
                                sqlite3_bind_text(server_.stmt_insert_event_, 2, payload.c_str(), -1, SQLITE_TRANSIENT);
                                sqlite3_step(server_.stmt_insert_event_);
                            } catch(...) {}
                        }

                        // 3. 将 shapes 每个元素写为 shape_add 事件
                        for (const auto& s : shapes_json) {
                            try {
                                json ev = {{"type","shape_add"}, {"shape", s}};
                                std::string payload = ev.dump();
                                sqlite3_reset(server_.stmt_insert_event_);
                                sqlite3_bind_text(server_.stmt_insert_event_, 1, doc_id.c_str(), -1, SQLITE_TRANSIENT);
                                sqlite3_bind_text(server_.stmt_insert_event_, 2, payload.c_str(), -1, SQLITE_TRANSIENT);
                                sqlite3_step(server_.stmt_insert_event_);
                            } catch(...) {}
                        }

                        // 4. 广播 load_save_applied 给所有在线用户
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
                } else if (msg_type == "delete_save") {
                    int64_t save_id = data.value("save_id", (int64_t)0);
                    std::string doc_id = room_->doc_id();
                    auto self = shared_from_this();
                    auto room_ref = room_;
                    server_.post_db_task([this, self, room_ref, save_id, doc_id]() {
                        sqlite3_reset(server_.stmt_delete_save_);
                        sqlite3_bind_int64(server_.stmt_delete_save_, 1, save_id);
                        sqlite3_bind_text(server_.stmt_delete_save_, 2, doc_id.c_str(), -1, SQLITE_TRANSIENT);
                        sqlite3_step(server_.stmt_delete_save_);
                        json res = {{"type","delete_save_res"},{"success",true},{"save_id",save_id}};
                        std::string resp_sender = res.dump();
                        json bcast = {{"type","save_deleted"},{"save_id",save_id}};
                        std::string resp_bcast = bcast.dump();
                        net::post(ws_.get_executor(), [self, room_ref, resp_sender, resp_bcast]() {
                            self->send(resp_sender);
                            room_ref->broadcast_except(self.get(), resp_bcast);
                        });
                    });
                } else if (msg_type == "cursor" || msg_type == "presence") {
                    room_->broadcast_except(this, payload);
                } else {
                    room_->save_event(payload); room_->broadcast_except(this, payload);
                }
            }
        } catch (...) {}
        do_read();
    }

    /**
     * @brief 线程安全地将消息投递到发送队列
     * @param message 待发送的 JSON 字符串
     */
    void send(const std::string& message) {
        net::post(ws_.get_executor(), [self = shared_from_this(), message]() {
            self->enqueue(message);
        });
    }

    /**
     * @brief 通过共享指针版本的消息投递，避免多路广播时的字符串拷贝
     * @param message 共享的消息内容
     */
    void send_shared(std::shared_ptr<const std::string> message) {
        net::post(ws_.get_executor(), [self = shared_from_this(), message]() {
            self->enqueue(*message);
        });
    }

private:
    /**
     * @brief 将消息加入 pending_ 队列，若写入空闲则启动批量定时器
     * @param msg 待发送的消息字符串
     */
    void enqueue(const std::string& msg) {
        pending_.push_back(msg);
        if (is_writing_) return;          // 正在发，等 on_write 结束后自动续上
        if (!timer_armed_) arm_timer();
    }

    /**
     * @brief 启动 2ms 批量聚合定时器，到期后触发 flush()
     */
    void arm_timer() {
        timer_armed_ = true;
        batch_timer_.expires_after(std::chrono::milliseconds(2));
        batch_timer_.async_wait([self = shared_from_this()](beast::error_code ec) {
            if (ec) return;
            self->timer_armed_ = false;
            if (!self->pending_.empty() && !self->is_writing_)
                self->flush();
        });
    }

    /**
     * @brief 将 pending_ 中所有消息打包为单帧后异步发送
     *
     * 若只有一条消息直接发送；多条消息则封装为
     * @c {"type":"batch","msgs":[...]} 格式。
     */
    void flush() {
        if (pending_.size() == 1) {
            write_buf_ = std::move(pending_[0]);
        } else {
            // {"type":"batch","msgs":[...]}
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

    /**
     * @brief 异步写入完成回调，若队列非空则继续 flush()
     * @param ec 错误码
     */
    void on_write(beast::error_code ec, std::size_t) {
        if (ec) return;
        is_writing_ = false;
        if (!pending_.empty()) {
            flush();
        }
    }
};

void Server::register_user(const std::string& username, Session* session) {
    std::lock_guard<std::mutex> lock(user_mutex_);
    auto it = active_users_.find(username);
    if (it != active_users_.end() && it->second != session) {
        it->second->send(R"({"type": "kicked", "msg": "您的账号已在其他设备登录，您被迫下线！"})");
        std::cout << "用户 " << username << " 的旧设备被踢下线。" << std::endl;
    }
    active_users_[username] = session;
}

void Server::unregister_user(const std::string& username, Session* session) {
    std::lock_guard<std::mutex> lock(user_mutex_);
    auto it = active_users_.find(username);
    if (it != active_users_.end() && it->second == session) {
        active_users_.erase(it);
    }
}

// Room 相关方法
void Room::join(Session* session) { std::lock_guard<std::mutex> lock(mutex_); sessions_.insert(session); }
void Room::leave(Session* session) { std::lock_guard<std::mutex> lock(mutex_); sessions_.erase(session); }
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
void Room::send_history(Session* session) {
    // 在 db_thread_ 中查询历史
    auto self_server = &server_;
    std::string doc_id_copy = doc_id_;
    server_.post_db_task([session, self_server, doc_id_copy]() {
        sqlite3_stmt* stmt = self_server->stmt_get_history_;
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
    });
}

/**
 * @brief 递归投递异步 accept，每接受一个连接即创建新 Session
 * @param ioc      io_context 引用
 * @param acceptor TCP 接受器
 * @param server   全局 Server 引用
 */
void do_accept(net::io_context& ioc, std::shared_ptr<tcp::acceptor> acceptor, Server& server) {
    acceptor->async_accept(net::make_strand(ioc),
        [&ioc, acceptor, &server](beast::error_code ec, tcp::socket socket) {
            if (!ec) std::make_shared<Session>(std::move(socket), server)->run();
            do_accept(ioc, acceptor, server);
        });
}

/**
 * @brief 程序入口，初始化 io_context、Server 及 TCP 监听器，启动多线程事件循环
 *
 * 监听地址为 0.0.0.0:9002，使用 2 个 I/O 线程处理并发连接。
 * @return 正常退出返回 0
 */
int main() {
    try {
        const int num_threads = 2;
        net::io_context ioc{num_threads};
        Server global_server;
        tcp::endpoint endpoint{net::ip::make_address("0.0.0.0"), 9002};
        auto acceptor = std::make_shared<tcp::acceptor>(ioc);
        beast::error_code ec;

        acceptor->open(endpoint.protocol(), ec);
        acceptor->set_option(net::socket_base::reuse_address(true), ec);
        acceptor->bind(endpoint, ec);
        acceptor->listen(net::socket_base::max_listen_connections, ec);
        do_accept(ioc, acceptor, global_server);

        std::cout << "🚀 服务器已启动: ws://0.0.0.0:9002" << std::endl;

        std::vector<std::thread> threads;
        threads.reserve(num_threads - 1);
        for (int i = 0; i < num_threads - 1; ++i)
            threads.emplace_back([&ioc] { ioc.run(); });
        ioc.run();
        for (auto& t : threads) t.join();
    } catch (...) {}
}
