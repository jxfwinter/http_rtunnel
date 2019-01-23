#ifndef WS_HTTP_SESSION_H
#define WS_HTTP_SESSION_H

#define TID "TID-J"
#define SETUP_MARK "SET-JRPROXY"

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

typedef boost::asio::coroutine Coroutine;
using namespace boost::beast;

typedef http::request<http::string_body> StrRequest;
typedef http::response<http::string_body> StrResponse;

struct HttpCoInfo
{
    string id;
    StrRequest req;
    StrResponse res;
    boost::beast::flat_buffer buffer;
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

class HttpTunnel
{
public:
    HttpTunnel(IoContext& ioc);
    ~HttpTunnel();

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
    void start_recv_co();
    void start_send_co(HttpCoInfoPtr co_info);

    void start_http_co(string id, StrRequest &req);

    void start_check_timer();
    void stop_check_timer();

    void loop_resolve(boost::system::error_code ec, ResolverResult r);
    void loop_conn(boost::system::error_code ec);
    void loop_recv(boost::system::error_code ec);
    void loop_http(boost::system::error_code ec, HttpCoInfoPtr co_info);
    void loop_send(boost::system::error_code ec);

    void loop_check(boost::system::error_code ec);

private:

    IoContext& m_ioc;
    boost::asio::steady_timer m_timer;
    TcpSocket m_socket;
    std::unique_ptr<Resolver> m_resolver;

    string m_local_ip = "0.0.0.0";
    uint16_t m_local_port = 9108;

    ConnectCallback m_conn_cb;

    string m_host;
    uint16_t m_port;
    //string m_target;

    ResolverResult m_resolve_result;
    StrRequest m_req;
    StrResponse m_res;

    SOCKET_STATUS m_socket_status = Disconnected;
    Coroutine m_resolve_co;
    Coroutine m_conn_co;
    Coroutine m_recv_co;
    Coroutine m_send_co;

    Coroutine m_timer_co;

    boost::beast::flat_buffer m_read_buffer;

    list<StrResponse> m_send_response_queue;
};

#endif // WS_SESSION_H
