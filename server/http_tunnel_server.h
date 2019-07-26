#ifndef HTTP_TUNNEL_SERVER_H
#define HTTP_TUNNEL_SERVER_H

#include "kconfig.h"

class HttpTunnelSession;

typedef std::shared_ptr<HttpTunnelSession> HttpTunnelSessionPtr;

struct InitSessionInfo
{
    string session_id;
    Coroutine co;
    TcpSocket socket;
    boost::beast::flat_buffer buffer;
    StringRequest req;
    StringResponse res;
    HttpTunnelSessionPtr session;
    InitSessionInfo(TcpSocket& s);
};
typedef shared_ptr<InitSessionInfo> InitSessionInfoPtr;

struct HttpSessionInfo
{
    Coroutine co;
    TcpSocket socket;
    boost::beast::flat_buffer buffer;
    StringRequest req;
    StringResponse res;
    string session_id;
    HttpTunnelSessionPtr session;

    HttpSessionInfo(TcpSocket& s);
};
typedef shared_ptr<HttpSessionInfo> HttpSessionInfoPtr;

class HttpTunnelServer
{
public:
    HttpTunnelServer(IoContext& ioc, const string &listen_address, uint16_t listen_port);
    ~HttpTunnelServer();

    void start();

    void stop();

    //添加session
    void add_tunnel_session(InitSessionInfoPtr init_info);
    //删除session
    void remove_tunnel_session(const string& session_id, HttpTunnelSessionPtr session);

    HttpTunnelSessionPtr find_session(const string& session_id);

private:
    void accept();

    void start_http_session(InitSessionInfoPtr init_info);

    void set_response(const StringRequest& req, http::status s, StringResponse& res);

private:
    void loop_accept(BSErrorCode ec);

    void loop_init_session(BSErrorCode ec, InitSessionInfoPtr co_info);

    void loop_http_session(BSErrorCode ec, HttpSessionInfoPtr co_info);


private:
    IoContext& m_ioc;
    Acceptor m_acceptor;
    TcpSocket m_socket;

    std::vector<std::thread> m_threads;
    Endpoint m_listen_ep;
    Coroutine m_accept_co;

    //key为session id
    std::unordered_map<string, HttpTunnelSessionPtr> m_sessions;
    std::mutex m_mutex;
};


#endif // HTTP_TUNNEL_SERVER_H
