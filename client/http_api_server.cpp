#include "http_api_server.h"
#include "pub.h"
#include <boost/process.hpp>
#include <boost/format.hpp>
namespace bp = boost::process;

#define KK_PRT(fmt...)   \
    do {\
    time_t timep;\
    time(&timep);\
    tm* tt = localtime(&timep); \
    printf("[%d-%02d-%02d %02d:%02d:%02d][%s]-%d: ", tt->tm_year+1900,tt->tm_mon+1,tt->tm_mday,tt->tm_hour,tt->tm_min,tt->tm_sec, __FUNCTION__, __LINE__);\
    printf(fmt);\
    printf("\n");\
    }while(0)

HttpApiServer::HttpApiServer(IoContext& ioc, const string& listen_address, uint16_t listen_port) :
    m_ioc(ioc), m_acceptor(m_ioc), m_socket(m_ioc), m_listen_address(listen_address), m_listen_port(listen_port)
{

}

void HttpApiServer::start()
{
    BSErrorCode ec;
    auto adr = boost::asio::ip::make_address(m_listen_address, ec);
    if(ec)
    {
        KK_PRT(ec.message().c_str());
        return;
    }
    Endpoint endpoint{adr, m_listen_port};
    m_acceptor.open(endpoint.protocol(), ec);
    if(ec)
    {
        KK_PRT(ec.message().c_str());
        return;
    }
    m_acceptor.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true), ec);
    m_acceptor.bind(endpoint, ec);
    if(ec)
    {
        KK_PRT(ec.message().c_str());
        return;
    }
    m_acceptor.listen(boost::asio::socket_base::max_listen_connections, ec);
    if(ec)
    {
        KK_PRT(ec.message().c_str());
        return;
    }

    int flags = fcntl(m_acceptor.native_handle(), F_GETFD);
    flags |= FD_CLOEXEC;
    fcntl(m_acceptor.native_handle(), F_SETFD, flags);

    loop_accept();
    return;
}

void HttpApiServer::start_session(TcpSocket s)
{
    HttpSessionCoInfoPtr co_info(new HttpSessionCoInfo(s));
    set_socket_opt(co_info->socket);
    loop_session({}, std::move(co_info));
}

#include <boost/asio/yield.hpp>
void HttpApiServer::loop_accept(BSErrorCode ec)
{
    if(ec)
    {
        cout << "async_accept end" << ec.message() << endl;
        KK_PRT(ec.message().c_str());
        return;
    }
    reenter(m_accept_co)
    {
        for(;;)
        {
            cout << "async_accept" << endl;
            yield m_acceptor.async_accept(m_socket, [this](BSErrorCode ec) {
                this->loop_accept(ec);
            });
            start_session(std::move(m_socket));
        }
    }
}

void HttpApiServer::loop_session(BSErrorCode ec, HttpSessionCoInfoPtr co_info)
{
    if(ec)
    {
        KK_PRT("http session failed, %s", ec.message().c_str());
        return;
    }
    reenter(co_info->session_co)
    {
        yield http::async_read(co_info->socket, co_info->buffer, co_info->req, [co_info, this](const BSErrorCode& ec, std::size_t) {
            this->loop_session(ec, co_info);
        });

        req_handler(co_info->req, co_info->res);

        //不支持长连接
        co_info->res.keep_alive(false);
        yield http::async_write(co_info->socket, co_info->res, [co_info, this](const BSErrorCode& ec, std::size_t) {
            this->loop_session(ec, co_info);
        });
        co_info->socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
        yield break;
    }
}

#include <boost/asio/unyield.hpp>

void HttpApiServer::req_handler(const StrRequest& req, StrResponse& res)
{
    cout << req << endl;
    res.body() = "ddd=111&ccc=333";
    res.prepare_payload();
    cout << res << endl;
}
