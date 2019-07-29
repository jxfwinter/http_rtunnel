#ifndef HTTP_TUNNEL_SERVER_H
#define HTTP_TUNNEL_SERVER_H

#include "kconfig.h"

class TunnelSession;

typedef std::shared_ptr<TunnelSession> TunnelSessionPtr;
typedef std::weak_ptr<TunnelSession> TunnelSessionWeakPtr;

struct InitSessionInfo
{
    bool https = false;
    string session_id;
    Coroutine co;
    TcpSocket socket;
    std::shared_ptr<SslSocket> ssl_socket;
    boost::beast::flat_buffer buffer;
    StringRequest req;
    StringResponse res;
    TunnelSessionWeakPtr session;
    InitSessionInfo(TcpSocket& s);
};
typedef std::shared_ptr<InitSessionInfo> InitSessionInfoPtr;

struct HttpSessionInfo
{
    bool https = false;
    Coroutine co;
    TcpSocket socket;
    std::shared_ptr<SslSocket> ssl_socket;
    boost::beast::flat_buffer buffer;
    StringRequest req;
    StringResponse res;
    string session_id;
    int timeout = 10;
    TunnelSessionPtr session;

    HttpSessionInfo(TcpSocket& s);
};
typedef std::shared_ptr<HttpSessionInfo> HttpSessionInfoPtr;

class HttpTunnelServer
{
public:
    HttpTunnelServer(IoContext& ioc);
    ~HttpTunnelServer();

    void start();

    void stop();

    //添加session
    void add_tunnel_session(InitSessionInfoPtr init_info);
    //删除session
    void remove_tunnel_session(const string& session_id, TunnelSessionPtr session);

    TunnelSessionPtr find_session(const string& session_id);

private:
    void start_init_session(TcpSocket s, bool https);

    void start_http_session(InitSessionInfoPtr init_info);

    void set_response(const StringRequest& req, http::status s, StringResponse& res);

private:
    void loop_http_accept(BSErrorCode ec);

    void loop_https_accept(BSErrorCode ec);

    void loop_init_session(BSErrorCode ec, InitSessionInfoPtr co_info);

    void loop_http_session(BSErrorCode ec, HttpSessionInfoPtr co_info);


private:
    IoContext& m_ioc;
    Acceptor m_http_acceptor;
    Acceptor m_https_acceptor;
    TcpSocket m_http_socket;
    TcpSocket m_https_socket;

    boost::asio::ssl::context m_ssl_cxt;

    Endpoint m_http_listen_ep;
    Coroutine m_http_accept_co;

    Endpoint m_https_listen_ep;
    Coroutine m_https_accept_co;

    //key为session id
    std::unordered_map<string, TunnelSessionPtr> m_sessions;
    std::mutex m_mutex;
};


#endif // HTTP_TUNNEL_SERVER_H
