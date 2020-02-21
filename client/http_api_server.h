#ifndef HTTP_API_SERVER_H
#define HTTP_API_SERVER_H

#include <string>
#include <iostream>
#include <boost/beast.hpp>
#include <boost/asio.hpp>
using namespace std;
namespace http = boost::beast::http;
typedef boost::asio::io_context IoContext;
typedef boost::asio::ip::tcp::resolver Resolver;
typedef boost::asio::ip::tcp::resolver::results_type ResolverResult;
typedef boost::asio::ip::tcp::acceptor Acceptor;

typedef boost::asio::ip::tcp::endpoint Endpoint;
typedef boost::asio::ip::tcp::socket TcpSocket;

typedef boost::system::error_code BSErrorCode;

typedef boost::asio::coroutine Coroutine;
using namespace boost::beast;

typedef http::request<http::string_body> StrRequest;
typedef http::response<http::string_body> StrResponse;

struct HttpSessionCoInfo
{
    Coroutine session_co;
    TcpSocket socket;
    boost::beast::flat_buffer buffer;
    StrRequest req;
    StrResponse res;

    HttpSessionCoInfo(TcpSocket& s) : socket(std::move(s))
    {

    }
};
typedef std::shared_ptr<HttpSessionCoInfo> HttpSessionCoInfoPtr;

class HttpApiServer
{
public:
    HttpApiServer(IoContext& ioc, const string &listen_address, uint16_t listen_port);
    ~HttpApiServer() = default;

    void start();

    //业务代码需要实现,在http_api_handler.cpp中实现
    void handler(HttpSessionCoInfoPtr co_info, std::function<void()> cb);

private:
    void loop_accept(BSErrorCode ec = {});

    void start_session(TcpSocket s);
    void loop_session(BSErrorCode ec, HttpSessionCoInfoPtr co_info);

private:
    void req_handler(const StrRequest& req, StrResponse& res);

private:
    IoContext& m_ioc;
    Acceptor m_acceptor;
    TcpSocket m_socket;
    string m_listen_address = "0.0.0.0";
    uint16_t m_listen_port;

    Coroutine m_accept_co;
};


#endif // HTTP_SERVER_H
