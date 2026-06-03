#include "../net/session.h"
#include "../core/server.h"
#include "../db/database.h"
#include "../util/sha256.h"

#include <sqlite3.h>

void Session::handle_register(const json& data, const std::string& /*raw*/) {
    std::string u = data.value("username", "");
    std::string hashed_p = sha256(data.value("password", ""));
    auto self = shared_from_this();
    server_.db().post_task([this, self, u, hashed_p]() {
        json res = {{"type", "register_res"}};
        sqlite3_reset(server_.db().stmt_insert_user_);
        sqlite3_bind_text(server_.db().stmt_insert_user_, 1, u.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(server_.db().stmt_insert_user_, 2, hashed_p.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(server_.db().stmt_insert_user_) == SQLITE_DONE) {
            res["success"] = true; res["msg"] = "Registration successful!";
        } else {
            res["success"] = false; res["msg"] = "Registration failed!";
        }
        std::string resp = res.dump();
        net::post(ws_.get_executor(), [self, resp]() { self->send(resp); });
    });
}

void Session::handle_login(const json& data, const std::string& /*raw*/) {
    std::string u = data.value("username", "");
    std::string hashed_p = sha256(data.value("password", ""));
    auto self = shared_from_this();
    server_.db().post_task([this, self, u, hashed_p]() {
        sqlite3_reset(server_.db().stmt_login_);
        sqlite3_bind_text(server_.db().stmt_login_, 1, u.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(server_.db().stmt_login_, 2, hashed_p.c_str(), -1, SQLITE_TRANSIENT);
        bool login_success = (sqlite3_step(server_.db().stmt_login_) == SQLITE_ROW);
        net::post(ws_.get_executor(), [self, this, u, login_success]() {
            json res = {{"type", "login_res"}};
            if (login_success) {
                username_ = u;
                server_.register_user(username_, self);
                res["success"] = true; res["username"] = u; res["msg"] = "Login successful!";
            } else {
                res["success"] = false; res["msg"] = "Invalid credentials!";
            }
            self->send(res.dump());
        });
    });
}
