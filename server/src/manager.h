#ifndef MANAGER_H
#define MANAGER_H

#include "kconfig.h"

class HttpTunnel;

typedef std::shared_ptr<HttpTunnel> HttpTunnelPtr;

class Manager
{
public:
    Manager();
    ~Manager();

    void start();

    void stop();

    //返回true成功, 返回false失败
    bool add_session(const string& session_id, HttpTunnelPtr session);
    //返回nullptr表示没找到
    HttpTunnelPtr find_session(const string& session_id);
    void remove_session(const string& session_id, HttpTunnelPtr session);

private:
    void accept();

    void process_http_req(RequestContext& cxt);

//    string req_to_buffer(StrRequest& req);
//    StrResponse buffer_to_res(const string& parser_buf);

private:
    RequestApiServer m_http_server;

    boost::asio::io_context m_io_cxt;
    int m_thread_count =  4;
    typedef boost::asio::executor_work_guard<boost::asio::io_context::executor_type> io_context_work;
    std::unique_ptr<io_context_work> m_work;

    boost::fibers::fiber m_accept_fiber;
    Acceptor m_acceptor;
    TcpSocket m_socket;
    std::vector<std::thread> m_threads;
    tcp::endpoint m_listen_ep;

    //key为session id
    std::unordered_map<string, HttpTunnelPtr> m_sessions;
    int m_tunnel_count = 0;
    boost::fibers::mutex m_mutex;
};


#endif // MANAGER_H
