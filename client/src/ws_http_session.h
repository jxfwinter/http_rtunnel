#ifndef WS_HTTP_SESSION_H
#define WS_HTTP_SESSION_H

#include <string>
#include <memory>
#include <map>
#include <list>
#include <functional>
#include <boost/beast.hpp>
#include <boost/asio/ip/tcp.hpp>
using namespace std;
typedef boost::asio::io_context IoContext;
typedef boost::asio::ip::tcp::resolver Resolver;
typedef boost::asio::ip::tcp::resolver::results_type ResolverResult;

typedef boost::asio::ip::tcp::endpoint Endpoint;
typedef boost::asio::ip::tcp::socket TcpSocket;

namespace address = boost::asio::ip::address;

typedef boost::asio::coroutine Coroutine;
namespace websocket = boost::beast::websocket;
typedef websocket::stream<TcpSocket> WebsocketStream;

struct HttpCoInfo
{
    string id;
    string req_buffer;
    string res_buffer;
    char read_buf[256];
    Coroutine http_co;
    TcpSocket http_socket;

    HttpCoInfo(IoContext& ioc) : http_socket(ioc)
    {

    }
};

typedef std::shared_ptr<HttpCoInfo> HttpCoInfoPtr;

enum SOCKET_STATUS {
   Disconnected = 0,
   Resolving = 1,
   Connecting = 2,
   Connected = 3
};

//连接状态回调
typedef std::function<void (SOCKET_STATUS)> ConnectCallback;

class WSHttpSession
{
public:
    WSHttpSession(IoContext& ioc);
    ~WSHttpSession();

    void set_transmit_local_address(string local_ip, uint16_t local_port) {
        m_local_ip = std::move(local_ip);
        m_local_port = local_port;
    }

    void set_conn_cb(ConnectCallback cb) {
        m_conn_cb = cb;
    }

    void start(string host, uint16_t port, string target);
    void stop();

private:
    void start_resolve_co();

    void start_conn_co();

    void start_ws_recv_co();

    void start_http_co(string id, string req_buf);

    void start_ws_send_res(HttpCoInfoPtr co_info);

    void start_check_timer();
    void stop_check_timer();

    void loop_resolve(boost::system::error_code ec, ResolverResult r);
    void loop_conn(boost::system::error_code ec);
    void loop_recv(boost::system::error_code ec);
    void loop_http(boost::system::error_code ec, size_t bytes_transferred, HttpCoInfoPtr co_info);
    void loop_send(boost::system::error_code ec);

    void loop_check(boost::system::error_code ec);

private:

    IoContext& m_ioc;
    boost::asio::steady_timer m_timer;
    WebsocketStream m_ws_stream;
    std::unique_ptr<Resolver> m_resolver;

    string m_local_ip = "0.0.0.0";
    uint16_t m_local_port = 9108;

    ConnectCallback m_conn_cb;

    string m_host;
    uint16_t m_port;
    string m_target;

    ResolverResult m_resolve_result;

    SOCKET_STATUS m_socket_status = Disconnected;
    Coroutine m_resolve_co;
    Coroutine m_conn_co;
    Coroutine m_recv_co;
    Coroutine m_send_co;

    Coroutine m_timer_co;

    boost::beast::flat_buffer m_read_buffer;

    list<string> m_send_queue;
};

#endif // WS_SESSION_H
