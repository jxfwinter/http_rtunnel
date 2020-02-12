#ifndef HTTP_TUNNEL_CLIENT_H
#define HTTP_TUNNEL_CLIENT_H

#define SESSION_ID "JR-SID"
#define TID "TID-J"

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
typedef std::function<void (SOCKET_STATUS)> ConnectStatusNotify;

class HttpTunnelClient;
typedef std::shared_ptr<HttpTunnelClient> HttpTunnelClientPtr;

//生存期与进程一致
class HttpTunnelClient : public std::enable_shared_from_this<HttpTunnelClient>
{
public:
    HttpTunnelClient(IoContext& ioc);
    ~HttpTunnelClient();

    void async_run(string host, uint16_t port, string session_id,
                   string local_ip, uint16_t local_port,
                   ConnectStatusNotify cb);

    void cancel();

private:
    void loop_run(boost::system::error_code ec);

    void start_http_co(string id, StrRequest& req);

    void start_send_co(HttpCoInfoPtr co_info);
    void loop_http(boost::system::error_code ec, HttpCoInfoPtr co_info);
    void loop_send(boost::system::error_code ec);

private:
    IoContext& m_ioc;
    boost::asio::steady_timer m_timer;
    TcpSocket m_socket;
    Resolver m_resolver;
    ResolverResult m_resolve_result;

    string m_local_ip = "0.0.0.0";
    uint16_t m_local_port = 9108;

    bool m_running = false;
    ConnectStatusNotify m_conn_notify_cb;

    string m_host;
    uint16_t m_port;
    string m_session_id;

    boost::beast::flat_buffer m_read_buffer;
    StrRequest m_req;
    StrResponse m_res;

    SOCKET_STATUS m_socket_status = Disconnected;
    Coroutine m_co;

    Coroutine m_send_co;
    list<StrResponse> m_send_response_queue;
};

#endif // HTTP_TUNNEL_CLIENT_H
