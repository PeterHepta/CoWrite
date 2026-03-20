#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/strand.hpp>
#include <nlohmann/json.hpp>
#include <sqlite3.h>
#include <iostream>
#include <memory>
#include <string>
#include <unordered_set>
#include <unordered_map>
#include <mutex>
#include <queue>
#include <thread>
#include <condition_variable>

namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;
namespace net = boost::asio;
using tcp = boost::asio::ip::tcp;
using json = nlohmann::json;

class Session;

struct DbTask {
    std::string doc_id;
    std::string payload;
};

class Session;
class Server; // 前向声明

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
        std::cout << "🏠 [房间] 文档 " << doc_id_ << " 被激活在内存中。" << std::endl;
    }

    void join(Session* session);
    void leave(Session* session);
    void broadcast_except(Session* sender, const std::string& message);
    void send_history(Session* session); 
    
    void save_event(const std::string& payload);

    uint32_t generate_site_id() { return next_site_id_++; }
};

class Server {
    std::unordered_map<std::string, std::shared_ptr<Room>> rooms_;
    std::mutex mutex_;
    sqlite3* db_ = nullptr;

    std::queue<DbTask> db_queue_;
    std::mutex db_mutex_;
    std::condition_variable db_cv_;
    std::thread db_thread_;
    bool stop_db_ = false;

public:
    Server() {
        if (sqlite3_open("collab_doc_v2.db", &db_)) {
            std::cerr << "无法打开数据库!" << std::endl; exit(1);
        }
        
        sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
        sqlite3_exec(db_, "PRAGMA synchronous=NORMAL;", nullptr, nullptr, nullptr);
        
        const char* sql = "CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, doc_id TEXT, payload TEXT);";
        sqlite3_exec(db_, sql, nullptr, nullptr, nullptr);

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

void Room::save_event(const std::string& payload) {
    server_.push_db_task(doc_id_, payload);
}

class Session : public std::enable_shared_from_this<Session> {
    websocket::stream<beast::tcp_stream> ws_;
    beast::flat_buffer buffer_;
    Server& server_;
    std::shared_ptr<Room> room_; 
    uint32_t site_id_ = 0;
    bool joined_ = false; 

    std::queue<std::string> write_queue_;
    bool is_writing_ = false;

public:
    Session(tcp::socket&& socket, Server& server)
        : ws_(std::move(socket)), server_(server) {}

    ~Session() { if (room_) room_->leave(this); }

    void run() {
        net::dispatch(ws_.get_executor(),
            beast::bind_front_handler(&Session::on_run, shared_from_this()));
    }

    void on_run() {
        ws_.async_accept(beast::bind_front_handler(&Session::on_accept, shared_from_this()));
    }

    void on_accept(beast::error_code ec) {
        if (ec) return;
        do_read();
    }

    void do_read() {
        ws_.async_read(buffer_, beast::bind_front_handler(&Session::on_read, shared_from_this()));
    }

    void on_read(beast::error_code ec, std::size_t bytes_transferred) {
        if (ec) return;
        std::string payload = beast::buffers_to_string(buffer_.data());
        buffer_.consume(buffer_.size());

        try {
            json data = json::parse(payload);
            
            if (!joined_) {
                if (data["type"] == "join") {
                    std::string doc_id = data["doc_id"];
                    room_ = server_.get_or_create_room(doc_id);
                    site_id_ = room_->generate_site_id();
                    room_->join(this);
                    joined_ = true;

                    // 发送初始化信息和历史记录
                    json init_msg = {{"type", "init"}, {"site_id", site_id_}};
                    send(init_msg.dump());
                    room_->send_history(this);

                    json presence_msg = {
                        {"type", "presence"}, 
                        {"action", "join"}, 
                        {"site_id", site_id_}
                    };
                    // 不存数据库，直接广播
                    room_->broadcast_except(this, presence_msg.dump());
                }
            } else {
                std::string msg_type = data.value("type", "");
                
                if (msg_type == "cursor" || msg_type == "presence") {
                    //  瞬态事件
                    room_->broadcast_except(this, payload);
                } else {
                    
                    room_->save_event(payload);
                    room_->broadcast_except(this, payload);
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "JSON 解析错误: " << e.what() << std::endl;
        }

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
        ws_.async_write(net::buffer(write_queue_.front()),
            beast::bind_front_handler(&Session::on_write, shared_from_this()));
    }

    void on_write(beast::error_code ec, std::size_t) {
        if (ec) return;
        write_queue_.pop();
        if (!write_queue_.empty()) do_write();
        else is_writing_ = false;
    }
};


void Room::join(Session* session) {
    std::lock_guard<std::mutex> lock(mutex_);
    sessions_.insert(session);
}

void Room::leave(Session* session) {
    std::lock_guard<std::mutex> lock(mutex_);
    sessions_.erase(session);
}

void Room::broadcast_except(Session* sender, const std::string& message) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto* session : sessions_) {
        if (session != sender) session->send(message);
    }
}

void Room::send_history(Session* session) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string sql = "SELECT payload FROM events WHERE doc_id = ? ORDER BY id ASC;";
    sqlite3_stmt* stmt;
    int count = 0;
    
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, doc_id_.c_str(), -1, SQLITE_TRANSIENT);
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            std::string payload = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            session->send(payload);
            count++;
        }
        sqlite3_finalize(stmt);
        std::cout << "⏪ [历史重播] 向新连入的用户发送了 " << count << " 条历史记录 (文档: " << doc_id_ << ")" << std::endl;
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

        tcp::endpoint endpoint{net::ip::make_address("127.0.0.1"), 9002};
        auto acceptor = std::make_shared<tcp::acceptor>(ioc);
        beast::error_code ec;
        
        acceptor->open(endpoint.protocol(), ec);
        acceptor->set_option(net::socket_base::reuse_address(true), ec);
        acceptor->bind(endpoint, ec);
        acceptor->listen(net::socket_base::max_listen_connections, ec);

        do_accept(ioc, acceptor, global_server);

        std::cout << "🚀 多文档房间服务器 (V2 数据库 + 雷达版) 已启动: ws://127.0.0.1:9002" << std::endl;
        ioc.run();
    } catch (...) {}
}