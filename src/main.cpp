#include "common.h"
#include "core/server.h"
#include "net/session.h"

#include <iostream>
#include <memory>
#include <thread>
#include <vector>

static void do_accept(net::io_context& ioc,
                      std::shared_ptr<tcp::acceptor> acceptor,
                      Server& server) {
    acceptor->async_accept(net::make_strand(ioc),
        [&ioc, acceptor, &server](beast::error_code ec, tcp::socket socket) {
            if (!ec) std::make_shared<Session>(std::move(socket), server)->run();
            do_accept(ioc, acceptor, server);
        });
}

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

        std::cout << "服务器已启动: ws://0.0.0.0:9002" << std::endl;

        std::vector<std::thread> threads;
        threads.reserve(num_threads - 1);
        for (int i = 0; i < num_threads - 1; ++i)
            threads.emplace_back([&ioc] { ioc.run(); });
        ioc.run();
        for (auto& t : threads) t.join();
    } catch (...) {}
}
