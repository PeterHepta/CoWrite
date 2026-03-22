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

struct DbTask {
    std::string doc_id;
    std::string payload;
};

class Room {
    std::string doc_id_;
    Server& server_;
    sqlite3* db_;
    std::unordered_set<Session*> sessions_;
    std::mutex mutex_;
    uint32_t next_site_id_ = 1;

public:
    Room(std::string doc_id, Server& server, sqlite3* db) 
        : doc_id_(std::move(doc_id)), server_(server), db_(db) {
        std::cout << "🏠 [Room] Document " << doc_id_ << " activated in memory." << std::endl;
    }

    void join(Session* session);
    void leave(Session* session);
    void broadcast_except(Session* sender, const std::string& message);
    void send_history(Session* session);
    void save_event(const std::string& payload);
    uint32_t generate_site_id() { return next_site_id_++; }
    const std::string& doc_id() const { return doc_id_; }
    bool has_session(Session* session) {
        std::lock_guard<std::mutex> lock(mutex_);
        return sessions_.count(session) > 0;
    }
};

class Server {
    std::unordered_map<std::string, std::shared_ptr<Room>> rooms_;
    std::mutex mutex_;

    std::queue<DbTask> db_queue_;
    std::mutex db_mutex_;
    std::condition_variable db_cv_;
    std::thread db_thread_;
    bool stop_db_ = false;

    std::unordered_map<std::string, Session*> active_users_;
    std::mutex user_mutex_;

public:
    sqlite3* db_ = nullptr;
    Server() {
        if (sqlite3_open("collab_doc_v2.db", &db_)) {
            std::cerr << "Failed to open database!" << std::endl; exit(1);
        }
        sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
        sqlite3_exec(db_, "PRAGMA synchronous=NORMAL;", nullptr, nullptr, nullptr);
        
        const char* sql = "CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, doc_id TEXT, payload TEXT);";
        sqlite3_exec(db_, sql, nullptr, nullptr, nullptr);

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
            std::cout << "✅ Account Database Ready!" << std::endl;
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

        db_thread_ = std::thread(&Server::db_worker_loop, this);
    }

    ~Server() { 
        {
            std::lock_guard<std::mutex> lock(db_mutex_);
            stop_db_ = true;
        }
        db_cv_.notify_all();
        if (db_thread_.joinable()) db_thread_.join();
        if (db_) sqlite3_close(db_); 
    }

    std::shared_ptr<Room> get_or_create_room(const std::string& doc_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (rooms_.find(doc_id) == rooms_.end()) {
            rooms_[doc_id] = std::make_shared<Room>(doc_id, *this, db_);
        }
        return rooms_[doc_id];
    }

    void push_db_task(const std::string& doc_id, const std::string& payload) {
        std::lock_guard<std::mutex> lock(db_mutex_);
        db_queue_.push({doc_id, payload});
        db_cv_.notify_one();
    }

    void register_user(const std::string& username, Session* session);
    void unregister_user(const std::string& username, Session* session);

    bool is_user_online(const std::string& username) {
        std::lock_guard<std::mutex> lock(user_mutex_);
        return active_users_.count(username) > 0;
    }

    Session* get_user_session(const std::string& username) {
        std::lock_guard<std::mutex> lock(user_mutex_);
        auto it = active_users_.find(username);
        return it != active_users_.end() ? it->second : nullptr;
    }

    std::string generate_invite_code() {
        static const char chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        static std::mt19937 rng(std::random_device{}());
        static std::uniform_int_distribution<int> dist(0, 35);
        std::string code(6, ' ');
        for (auto& c : code) c = chars[dist(rng)];
        return code;
    }

    std::string generate_doc_id(const std::string& username) {
        auto ts = std::chrono::steady_clock::now().time_since_epoch().count();
        return username + "_" + std::to_string(ts);
    }

private:
    void db_worker_loop() {
        std::string sql = "INSERT INTO events (doc_id, payload) VALUES (?, ?);";
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) return;

        while (true) {
            DbTask task;
            {
                std::unique_lock<std::mutex> lock(db_mutex_);
                db_cv_.wait(lock, [this]{ return !db_queue_.empty() || stop_db_; });
                if (stop_db_ && db_queue_.empty()) break;
                
                task = std::move(db_queue_.front());
                db_queue_.pop();
            }
            sqlite3_bind_text(stmt, 1, task.doc_id.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 2, task.payload.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(stmt);
            sqlite3_reset(stmt);
            sqlite3_clear_bindings(stmt);
        }
        sqlite3_finalize(stmt);
    }
};

void Room::save_event(const std::string& payload) { server_.push_db_task(doc_id_, payload); }

class Session : public std::enable_shared_from_this<Session> {
    websocket::stream<beast::tcp_stream> ws_;
    beast::flat_buffer buffer_;
    Server& server_;
    std::shared_ptr<Room> room_; 
    uint32_t site_id_ = 0;
    bool joined_ = false; 

    std::queue<std::string> write_queue_;
    bool is_writing_ = false;

    std::string username_; 

public:
    Session(tcp::socket&& socket, Server& server)
        : ws_(std::move(socket)), server_(server) {}

    ~Session() { 
        if (!username_.empty()) server_.unregister_user(username_, this);
        if (room_) room_->leave(this); 
    }

    void run() { net::dispatch(ws_.get_executor(), beast::bind_front_handler(&Session::on_run, shared_from_this())); }
    void on_run() { ws_.async_accept(beast::bind_front_handler(&Session::on_accept, shared_from_this())); }
    void on_accept(beast::error_code ec) { if (!ec) do_read(); }
    void do_read() { ws_.async_read(buffer_, beast::bind_front_handler(&Session::on_read, shared_from_this())); }

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
                    std::string p = data.value("password", "");
                    std::string hashed_p = sha256(p);
                    json res = {{"type", "register_res"}};
                    sqlite3_stmt* stmt;
                    if (sqlite3_prepare_v2(server_.db_, "INSERT INTO users (username, password) VALUES (?, ?);", -1, &stmt, nullptr) == SQLITE_OK) {
                        sqlite3_bind_text(stmt, 1, u.c_str(), -1, SQLITE_TRANSIENT);
                        sqlite3_bind_text(stmt, 2, hashed_p.c_str(), -1, SQLITE_TRANSIENT);
                        if (sqlite3_step(stmt) == SQLITE_DONE) {
                            res["success"] = true; res["msg"] = "Registration successful!";
                        } else {
                            res["success"] = false; res["msg"] = "Registration failed!";
                        }
                        sqlite3_finalize(stmt);
                    } else {
                        res["success"] = false; res["msg"] = "Registration failed!";
                    }
                    send(res.dump());
                }
                else if (msg_type == "login") {
                    std::string u = data.value("username", "");
                    std::string p = data.value("password", "");
                    std::string hashed_p = sha256(p);
                    json res = {{"type", "login_res"}};
                    bool login_success = false;
                    sqlite3_stmt* stmt;
                    if (sqlite3_prepare_v2(server_.db_, "SELECT id FROM users WHERE username = ? AND password = ?;", -1, &stmt, nullptr) == SQLITE_OK) {
                        sqlite3_bind_text(stmt, 1, u.c_str(), -1, SQLITE_TRANSIENT);
                        sqlite3_bind_text(stmt, 2, hashed_p.c_str(), -1, SQLITE_TRANSIENT);
                        login_success = (sqlite3_step(stmt) == SQLITE_ROW);
                        sqlite3_finalize(stmt);
                    }
                    if (login_success) {
                        username_ = u;
                        server_.register_user(username_, this);
                        res["success"] = true; res["username"] = u; res["msg"] = "Login successful!";
                    } else {
                        res["success"] = false; res["msg"] = "Invalid credentials!";
                    }
                    send(res.dump());
                } 
                else if (msg_type == "create_room") {
                    if (username_.empty()) {
                        send(R"({"type":"create_room_res","success":false,"msg":"请先登录"})");
                    } else {
                        std::string doc_id = server_.generate_doc_id(username_);
                        std::string room_name = data.value("room_name", "未命名房间");
                        std::string code;
                        while (true) {
                            code = server_.generate_invite_code();
                            sqlite3_stmt* chk;
                            sqlite3_prepare_v2(server_.db_, "SELECT id FROM invite_codes WHERE code=?;", -1, &chk, nullptr);
                            sqlite3_bind_text(chk, 1, code.c_str(), -1, SQLITE_TRANSIENT);
                            bool exists = (sqlite3_step(chk) == SQLITE_ROW);
                            sqlite3_finalize(chk);
                            if (!exists) break;
                        }

                        // invite_type: "once" | "timed" | "permanent"
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

                        sqlite3_stmt* ins;
                        sqlite3_prepare_v2(server_.db_,
                            "INSERT INTO invite_codes (code, doc_id, room_name, created_by, max_uses, expires_at) VALUES (?,?,?,?,?,?);",
                            -1, &ins, nullptr);
                        sqlite3_bind_text(ins, 1, code.c_str(), -1, SQLITE_TRANSIENT);
                        sqlite3_bind_text(ins, 2, doc_id.c_str(), -1, SQLITE_TRANSIENT);
                        sqlite3_bind_text(ins, 3, room_name.c_str(), -1, SQLITE_TRANSIENT);
                        sqlite3_bind_text(ins, 4, username_.c_str(), -1, SQLITE_TRANSIENT);
                        sqlite3_bind_int(ins, 5, max_uses);
                        if (expires_at > 0) sqlite3_bind_int64(ins, 6, expires_at);
                        else sqlite3_bind_null(ins, 6);
                        sqlite3_step(ins);
                        sqlite3_finalize(ins);

                        json res = {{"type", "create_room_res"}, {"success", true},
                                    {"code", code}, {"doc_id", doc_id},
                                    {"room_name", room_name}, {"invite_type", invite_type}};
                        if (expires_at > 0) res["expires_at"] = expires_at;
                        send(res.dump());
                        std::cout << "🎉 用户 " << username_ << " 创建房间 [" << room_name << "] "
                                  << doc_id << "，邀请码: " << code << " [" << invite_type << "]" << std::endl;
                    }
                }
                else if (msg_type == "join_with_code") {
                    std::string code = data.value("code", "");
                    if (username_.empty()) {
                        send(R"({"type":"join_with_code_res","success":false,"msg":"请先登录"})");
                    } else if (code.empty()) {
                        send(R"({"type":"join_with_code_res","success":false,"msg":"邀请码不能为空"})");
                    } else {
                        // 查询邀请码：一次性(max_uses=1,used=0) 或 时效/永久(max_uses=-1)
                        sqlite3_stmt* sel;
                        sqlite3_prepare_v2(server_.db_,
                            "SELECT doc_id, room_name, max_uses, expires_at FROM invite_codes WHERE code=? AND (max_uses=-1 OR used=0);",
                            -1, &sel, nullptr);
                        sqlite3_bind_text(sel, 1, code.c_str(), -1, SQLITE_TRANSIENT);
                        json res = {{"type", "join_with_code_res"}};
                        if (sqlite3_step(sel) == SQLITE_ROW) {
                            std::string doc_id = reinterpret_cast<const char*>(sqlite3_column_text(sel, 0));
                            std::string room_name = reinterpret_cast<const char*>(sqlite3_column_text(sel, 1));
                            int max_uses = sqlite3_column_int(sel, 2);
                            bool has_expiry = (sqlite3_column_type(sel, 3) != SQLITE_NULL);
                            int64_t expires_at = has_expiry ? sqlite3_column_int64(sel, 3) : 0;
                            sqlite3_finalize(sel);

                            // 检查是否过期
                            if (has_expiry) {
                                auto now = std::chrono::system_clock::now().time_since_epoch();
                                int64_t now_sec = std::chrono::duration_cast<std::chrono::seconds>(now).count();
                                if (now_sec > expires_at) {
                                    res["success"] = false; res["msg"] = "邀请码已过期";
                                    send(res.dump());
                                    do_read(); return;
                                }
                            }

                            // 一次性：标记已用
                            if (max_uses == 1) {
                                sqlite3_stmt* upd;
                                sqlite3_prepare_v2(server_.db_, "UPDATE invite_codes SET used=1 WHERE code=?;", -1, &upd, nullptr);
                                sqlite3_bind_text(upd, 1, code.c_str(), -1, SQLITE_TRANSIENT);
                                sqlite3_step(upd);
                                sqlite3_finalize(upd);
                            }

                            res["success"] = true; res["doc_id"] = doc_id; res["room_name"] = room_name;
                            std::cout << "🔓 用户 " << username_ << " 使用邀请码 " << code << " 加入房间 " << doc_id << std::endl;
                        } else {
                            sqlite3_finalize(sel);
                            res["success"] = false; res["msg"] = "邀请码无效或已被使用";
                        }
                        send(res.dump());
                    }
                }
                else if (msg_type == "join") {
                    std::string doc_id = data.value("doc_id", "public_room");
                    room_ = server_.get_or_create_room(doc_id);
                    int req_site = data.value("requested_site_id", 0);
                    if (req_site > 0) site_id_ = req_site; else site_id_ = room_->generate_site_id();

                    room_->join(this);
                    joined_ = true;

                    // 记录成员关系（INSERT OR IGNORE 保证幂等）
                    {
                        sqlite3_stmt* mem_stmt;
                        sqlite3_prepare_v2(server_.db_,
                            "INSERT OR IGNORE INTO room_members (username, doc_id) VALUES (?, ?);",
                            -1, &mem_stmt, nullptr);
                        sqlite3_bind_text(mem_stmt, 1, username_.c_str(), -1, SQLITE_TRANSIENT);
                        sqlite3_bind_text(mem_stmt, 2, doc_id.c_str(), -1, SQLITE_TRANSIENT);
                        sqlite3_step(mem_stmt);
                        sqlite3_finalize(mem_stmt);
                    }

                    // 查出房间名
                    std::string room_name;
                    sqlite3_stmt* nm;
                    sqlite3_prepare_v2(server_.db_, "SELECT room_name FROM invite_codes WHERE doc_id=? LIMIT 1;", -1, &nm, nullptr);
                    sqlite3_bind_text(nm, 1, doc_id.c_str(), -1, SQLITE_TRANSIENT);
                    if (sqlite3_step(nm) == SQLITE_ROW) room_name = reinterpret_cast<const char*>(sqlite3_column_text(nm, 0));
                    sqlite3_finalize(nm);

                    json init_msg = {{"type", "init"}, {"site_id", site_id_}, {"room_name", room_name}};
                    send(init_msg.dump());
                    room_->send_history(this);

                    json presence_msg = {{"type", "presence"}, {"action", "join"}, {"site_id", site_id_}, {"username", username_}};
                    room_->broadcast_except(this, presence_msg.dump());
                }
                else if (msg_type == "get_my_rooms") {
                    if (username_.empty()) {
                        send(R"({"type":"get_my_rooms_res","success":false,"msg":"请先登录"})");
                    } else {
                        sqlite3_stmt* sel;
                        const char* sql =
                            "SELECT rm.doc_id, "
                            "       COALESCE(MAX(ic.room_name), rm.doc_id) AS room_name, "
                            "       COALESCE(MAX(ic.created_by), '') AS created_by, "
                            "       COALESCE(MAX(ic.created_at), 0) AS created_at, "
                            "       rm.joined_at "
                            "FROM room_members rm "
                            "LEFT JOIN invite_codes ic ON ic.doc_id = rm.doc_id "
                            "WHERE rm.username = ? "
                            "GROUP BY rm.doc_id "
                            "ORDER BY rm.joined_at DESC;";
                        if (sqlite3_prepare_v2(server_.db_, sql, -1, &sel, nullptr) == SQLITE_OK) {
                            sqlite3_bind_text(sel, 1, username_.c_str(), -1, SQLITE_TRANSIENT);
                            json rooms = json::array();
                            while (sqlite3_step(sel) == SQLITE_ROW) {
                                json r;
                                auto col_text = [&](int col) -> std::string {
                                    const char* t = reinterpret_cast<const char*>(sqlite3_column_text(sel, col));
                                    return t ? t : "";
                                };
                                r["doc_id"]     = col_text(0);
                                r["room_name"]  = col_text(1);
                                r["created_by"] = col_text(2);
                                r["created_at"] = sqlite3_column_int64(sel, 3);
                                r["joined_at"]  = sqlite3_column_int64(sel, 4);
                                rooms.push_back(r);
                            }
                            sqlite3_finalize(sel);
                            json res = {{"type", "get_my_rooms_res"}, {"success", true}, {"rooms", rooms}};
                            send(res.dump());
                        } else {
                            send(R"({"type":"get_my_rooms_res","success":false,"msg":"查询失败"})");
                        }
                    }
                }
                else if (msg_type == "rejoin_room") {
                    std::string doc_id = data.value("doc_id", "");
                    if (username_.empty()) {
                        send(R"({"type":"rejoin_room_res","success":false,"msg":"请先登录"})");
                    } else if (doc_id.empty()) {
                        send(R"({"type":"rejoin_room_res","success":false,"msg":"doc_id 不能为空"})");
                    } else {
                        // 验证用户在该房间有成员记录
                        sqlite3_stmt* chk;
                        sqlite3_prepare_v2(server_.db_,
                            "SELECT id FROM room_members WHERE username=? AND doc_id=?;",
                            -1, &chk, nullptr);
                        sqlite3_bind_text(chk, 1, username_.c_str(), -1, SQLITE_TRANSIENT);
                        sqlite3_bind_text(chk, 2, doc_id.c_str(),    -1, SQLITE_TRANSIENT);
                        bool is_member = (sqlite3_step(chk) == SQLITE_ROW);
                        sqlite3_finalize(chk);

                        if (!is_member) {
                            send(R"({"type":"rejoin_room_res","success":false,"msg":"您没有该房间的访问权限"})");
                        } else {
                            room_ = server_.get_or_create_room(doc_id);
                            int req_site = data.value("requested_site_id", 0);
                            if (req_site > 0) site_id_ = req_site;
                            else site_id_ = room_->generate_site_id();

                            room_->join(this);
                            joined_ = true;

                            std::string room_name;
                            sqlite3_stmt* nm;
                            sqlite3_prepare_v2(server_.db_,
                                "SELECT room_name FROM invite_codes WHERE doc_id=? LIMIT 1;",
                                -1, &nm, nullptr);
                            sqlite3_bind_text(nm, 1, doc_id.c_str(), -1, SQLITE_TRANSIENT);
                            if (sqlite3_step(nm) == SQLITE_ROW)
                                room_name = reinterpret_cast<const char*>(sqlite3_column_text(nm, 0));
                            sqlite3_finalize(nm);

                            json init_msg = {{"type", "init"}, {"site_id", site_id_}, {"room_name", room_name}};
                            send(init_msg.dump());
                            room_->send_history(this);

                            json presence_msg = {{"type","presence"},{"action","join"},
                                                 {"site_id", site_id_},{"username", username_}};
                            room_->broadcast_except(this, presence_msg.dump());
                        }
                    }
                }
            } else {
                std::string msg_type = data.value("type", "");
                if (msg_type == "gen_invite") {
                    // 验证当前用户是否为房间创建者
                    sqlite3_stmt* chk;
                    sqlite3_prepare_v2(server_.db_,
                        "SELECT created_by FROM invite_codes WHERE doc_id=? LIMIT 1;",
                        -1, &chk, nullptr);
                    sqlite3_bind_text(chk, 1, room_->doc_id().c_str(), -1, SQLITE_TRANSIENT);
                    bool is_owner = false;
                    if (sqlite3_step(chk) == SQLITE_ROW) {
                        std::string creator = reinterpret_cast<const char*>(sqlite3_column_text(chk, 0));
                        is_owner = (creator == username_);
                    }
                    sqlite3_finalize(chk);

                    if (!is_owner) {
                        send(R"({"type":"gen_invite_res","success":false,"msg":"只有房间创建者才能生成邀请码"})");
                    } else {
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
                        std::string code;
                        while (true) {
                            code = server_.generate_invite_code();
                            sqlite3_stmt* chk2;
                            sqlite3_prepare_v2(server_.db_, "SELECT id FROM invite_codes WHERE code=?;", -1, &chk2, nullptr);
                            sqlite3_bind_text(chk2, 1, code.c_str(), -1, SQLITE_TRANSIENT);
                            bool exists = (sqlite3_step(chk2) == SQLITE_ROW);
                            sqlite3_finalize(chk2);
                            if (!exists) break;
                        }
                        std::string room_name = "未命名房间";
                        sqlite3_stmt* nm;
                        sqlite3_prepare_v2(server_.db_, "SELECT room_name FROM invite_codes WHERE doc_id=? LIMIT 1;", -1, &nm, nullptr);
                        sqlite3_bind_text(nm, 1, room_->doc_id().c_str(), -1, SQLITE_TRANSIENT);
                        if (sqlite3_step(nm) == SQLITE_ROW) room_name = reinterpret_cast<const char*>(sqlite3_column_text(nm, 0));
                        sqlite3_finalize(nm);

                        sqlite3_stmt* ins;
                        sqlite3_prepare_v2(server_.db_,
                            "INSERT INTO invite_codes (code, doc_id, room_name, created_by, max_uses, expires_at) VALUES (?,?,?,?,?,?);",
                            -1, &ins, nullptr);
                        sqlite3_bind_text(ins, 1, code.c_str(), -1, SQLITE_TRANSIENT);
                        sqlite3_bind_text(ins, 2, room_->doc_id().c_str(), -1, SQLITE_TRANSIENT);
                        sqlite3_bind_text(ins, 3, room_name.c_str(), -1, SQLITE_TRANSIENT);
                        sqlite3_bind_text(ins, 4, username_.c_str(), -1, SQLITE_TRANSIENT);
                        sqlite3_bind_int(ins, 5, max_uses);
                        if (expires_at > 0) sqlite3_bind_int64(ins, 6, expires_at);
                        else sqlite3_bind_null(ins, 6);
                        sqlite3_step(ins);
                        sqlite3_finalize(ins);

                        json res = {{"type", "gen_invite_res"}, {"success", true},
                                    {"code", code}, {"invite_type", invite_type}};
                        if (expires_at > 0) res["expires_at"] = expires_at;
                        send(res.dump());
                        std::cout << "🔑 用户 " << username_ << " 在房间 " << room_->doc_id()
                                  << " 生成新邀请码: " << code << " [" << invite_type << "]" << std::endl;
                    }
                } else if (msg_type == "rename_room") {
                    std::string new_name = data.value("room_name", "");
                    if (new_name.empty()) {
                        send(R"({"type":"rename_room_res","success":false,"msg":"房间名不能为空"})");
                    } else {
                        // 验证当前用户是否为房间创建者
                        sqlite3_stmt* chk;
                        sqlite3_prepare_v2(server_.db_,
                            "SELECT created_by FROM invite_codes WHERE doc_id=? LIMIT 1;",
                            -1, &chk, nullptr);
                        sqlite3_bind_text(chk, 1, room_->doc_id().c_str(), -1, SQLITE_TRANSIENT);
                        bool is_owner = false;
                        if (sqlite3_step(chk) == SQLITE_ROW) {
                            std::string creator = reinterpret_cast<const char*>(sqlite3_column_text(chk, 0));
                            is_owner = (creator == username_);
                        }
                        sqlite3_finalize(chk);

                        if (!is_owner) {
                            send(R"({"type":"rename_room_res","success":false,"msg":"只有房间创建者才能修改房间名"})");
                        } else {
                            sqlite3_stmt* upd;
                            sqlite3_prepare_v2(server_.db_,
                                "UPDATE invite_codes SET room_name=? WHERE doc_id=?;",
                                -1, &upd, nullptr);
                            sqlite3_bind_text(upd, 1, new_name.c_str(), -1, SQLITE_TRANSIENT);
                            sqlite3_bind_text(upd, 2, room_->doc_id().c_str(), -1, SQLITE_TRANSIENT);
                            sqlite3_step(upd);
                            sqlite3_finalize(upd);
                            json res = {{"type", "rename_room_res"}, {"success", true}, {"room_name", new_name}};
                            send(res.dump());
                            std::cout << "✏️ 用户 " << username_ << " 将房间 " << room_->doc_id()
                                      << " 重命名为: " << new_name << std::endl;
                        }
                    }
                } else if (msg_type == "get_room_members") {
                    // 先查出创建者
                    std::string room_owner;
                    {
                        sqlite3_stmt* own;
                        sqlite3_prepare_v2(server_.db_,
                            "SELECT created_by FROM invite_codes WHERE doc_id=? LIMIT 1;",
                            -1, &own, nullptr);
                        sqlite3_bind_text(own, 1, room_->doc_id().c_str(), -1, SQLITE_TRANSIENT);
                        if (sqlite3_step(own) == SQLITE_ROW)
                            room_owner = reinterpret_cast<const char*>(sqlite3_column_text(own, 0));
                        sqlite3_finalize(own);
                    }
                    // 查询该房间的所有历史成员及其在线状态
                    sqlite3_stmt* sel;
                    sqlite3_prepare_v2(server_.db_,
                        "SELECT username FROM room_members WHERE doc_id=? ORDER BY joined_at ASC;",
                        -1, &sel, nullptr);
                    sqlite3_bind_text(sel, 1, room_->doc_id().c_str(), -1, SQLITE_TRANSIENT);
                    json members = json::array();
                    while (sqlite3_step(sel) == SQLITE_ROW) {
                        std::string uname = reinterpret_cast<const char*>(sqlite3_column_text(sel, 0));
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
                    sqlite3_finalize(sel);
                    json res = {{"type", "get_room_members_res"}, {"success", true}, {"members", members}};
                    send(res.dump());
                } else if (msg_type == "cursor" || msg_type == "presence") {
                    room_->broadcast_except(this, payload);
                } else {
                    room_->save_event(payload); room_->broadcast_except(this, payload);
                }            }
        } catch (...) {}
        do_read();
    }

    void send(const std::string& message) {
        net::post(ws_.get_executor(), beast::bind_front_handler(&Session::on_send, shared_from_this(), message));
    }

private:
    void on_send(std::string message) {
        write_queue_.push(std::move(message));
        if (!is_writing_) do_write();
    }
    void do_write() {
        is_writing_ = true;
        ws_.text(true);
        ws_.async_write(net::buffer(write_queue_.front()), beast::bind_front_handler(&Session::on_write, shared_from_this()));
    }
    void on_write(beast::error_code ec, std::size_t) {
        if (ec) return;
        write_queue_.pop();
        if (!write_queue_.empty()) do_write(); else is_writing_ = false;
    }
};

void Server::register_user(const std::string& username, Session* session) {
    std::lock_guard<std::mutex> lock(user_mutex_);
    auto it = active_users_.find(username);
    if (it != active_users_.end() && it->second != session) {
        it->second->send(R"({"type": "kicked", "msg": "您的账号已在其他设备登录，您被迫下线！"})");
        std::cout << "⚠️ 用户 " << username << " 的旧设备被踢下线。" << std::endl;
    }
    active_users_[username] = session; // 记录新设备
}

void Server::unregister_user(const std::string& username, Session* session) {
    std::lock_guard<std::mutex> lock(user_mutex_);
    auto it = active_users_.find(username);
    if (it != active_users_.end() && it->second == session) {
        active_users_.erase(it); // 用户断开连接，划掉名字
    }
}

// Room 相关方法
void Room::join(Session* session) { std::lock_guard<std::mutex> lock(mutex_); sessions_.insert(session); }
void Room::leave(Session* session) { std::lock_guard<std::mutex> lock(mutex_); sessions_.erase(session); }
void Room::broadcast_except(Session* sender, const std::string& message) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto* session : sessions_) if (session != sender) session->send(message);
}
void Room::send_history(Session* session) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string sql = "SELECT payload FROM events WHERE doc_id = ? ORDER BY id ASC;";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, doc_id_.c_str(), -1, SQLITE_TRANSIENT);
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            session->send(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0)));
        }
        sqlite3_finalize(stmt);
    }
}

void do_accept(net::io_context& ioc, std::shared_ptr<tcp::acceptor> acceptor, Server& server) {
    acceptor->async_accept(net::make_strand(ioc),
        [&ioc, acceptor, &server](beast::error_code ec, tcp::socket socket) {
            if (!ec) std::make_shared<Session>(std::move(socket), server)->run();
            do_accept(ioc, acceptor, server);
        });
}

int main() {
    try {
        net::io_context ioc{1};
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
        ioc.run();
    } catch (...) {}
}
