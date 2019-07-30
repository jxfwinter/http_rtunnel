#include "http_tunnel_server.h"
#include "http_tunnel_session.h"
#include "https_tunnel_session.h"

static void set_socket_opt(TcpSocket& socket)
{
    //boost::asio::socket_base::keep_alive opt_keep_alive(true);
    //socket.set_option(opt_keep_alive);

    int flags = 1;
    int tcp_keepalive_time = 20;
    int tcp_keepalive_probes = 3;
    int tcp_keepalive_intvl = 3;

    int ret = 0;
    ret = setsockopt(socket.native_handle(), SOL_SOCKET, SO_KEEPALIVE, &flags, sizeof(flags));
    if(ret < 0)
    {
        log_error_ext("setsockopt SO_KEEPALIVE failed");
    }
    ret = setsockopt(socket.native_handle(), IPPROTO_TCP, TCP_KEEPIDLE, &tcp_keepalive_time, sizeof(tcp_keepalive_time));
    if(ret < 0)
    {
        log_error_ext("setsockopt TCP_KEEPIDLE failed");
    }
    ret = setsockopt(socket.native_handle(), IPPROTO_TCP, TCP_KEEPINTVL, &tcp_keepalive_intvl, sizeof(tcp_keepalive_intvl));
    if(ret < 0)
    {
        log_error_ext("setsockopt TCP_KEEPINTVL failed");
    }
    ret = setsockopt(socket.native_handle(), IPPROTO_TCP, TCP_KEEPCNT, &tcp_keepalive_probes, sizeof(tcp_keepalive_probes));
    if(ret < 0)
    {
        log_error_ext("setsockopt TCP_KEEPCNT failed");
    }
}

InitSessionInfo::InitSessionInfo(TcpSocket& s) : socket(std::move(s))
{

}

HttpSessionInfo::HttpSessionInfo(TcpSocket& s) : socket(std::move(s))
{

}

HttpTunnelServer::HttpTunnelServer(IoContext &ioc):
    m_ioc(ioc), m_http_acceptor(m_ioc), m_https_acceptor(m_ioc), m_http_socket(m_ioc), m_https_socket(m_ioc), m_ssl_cxt(boost::asio::ssl::context::sslv23)
{
    m_http_listen_ep = Endpoint{boost::asio::ip::make_address(g_cfg->http_listen_addr), g_cfg->http_listen_port};
    m_https_listen_ep = Endpoint{boost::asio::ip::make_address(g_cfg->https_listen_addr), g_cfg->https_listen_port};

    m_ssl_cxt.set_options(boost::asio::ssl::context::default_workarounds);
    m_ssl_cxt.use_certificate_file(g_cfg->ssl_certificate, boost::asio::ssl::context::pem);
    m_ssl_cxt.use_private_key_file(g_cfg->ssl_certificate_key, boost::asio::ssl::context::pem);
}

HttpTunnelServer::~HttpTunnelServer()
{

}

void HttpTunnelServer::start()
{
    {
        //监听http端口
        BSErrorCode ec;
        m_http_acceptor.open(m_http_listen_ep.protocol(), ec);
        if(ec)
        {
            log_error_ext(ec.message());
            return;
        }

        m_http_acceptor.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true), ec);
        m_http_acceptor.bind(m_http_listen_ep, ec);
        if(ec)
        {
            log_error_ext(ec.message());
            return;
        }
        m_http_acceptor.listen(boost::asio::socket_base::max_listen_connections, ec);
        if(ec)
        {
            log_error_ext(ec.message());
            return;
        }

        loop_http_accept({});
    }

    {
        //监听https端口
        BSErrorCode ec;
        m_https_acceptor.open(m_https_listen_ep.protocol(), ec);
        if(ec)
        {
            log_error_ext(ec.message());
            return;
        }

        m_https_acceptor.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true), ec);
        m_https_acceptor.bind(m_https_listen_ep, ec);
        if(ec)
        {
            log_error_ext(ec.message());
            return;
        }
        m_https_acceptor.listen(boost::asio::socket_base::max_listen_connections, ec);
        if(ec)
        {
            log_error_ext(ec.message());
            return;
        }

        loop_https_accept({});
    }
    return;
}

void HttpTunnelServer::stop()
{
    BSErrorCode ec;
    m_http_acceptor.close(ec);
}

void HttpTunnelServer::start_init_session(TcpSocket s, bool https)
{
    InitSessionInfoPtr co_info(new InitSessionInfo(s));
    co_info->https = https;
    set_socket_opt(co_info->socket);
    loop_init_session({}, std::move(co_info));
}

void HttpTunnelServer::start_http_session(InitSessionInfoPtr init_info)
{
    HttpSessionInfoPtr co_info(new HttpSessionInfo(init_info->socket));
    co_info->https = init_info->https;
    if(co_info->https)
    {
        co_info->ssl_socket = init_info->ssl_socket;
    }
    co_info->timeout = g_cfg->req_timeout_secs;
    co_info->req = std::move(init_info->req);
    loop_http_session({}, co_info);
}

#include <boost/asio/yield.hpp>
void HttpTunnelServer::loop_http_accept(BSErrorCode ec)
{
    reenter(m_http_accept_co)
    {
        for(;;)
        {
            yield m_http_acceptor.async_accept(m_http_socket, [this](BSErrorCode ec) {
                this->loop_http_accept(ec);
            });
            if(ec == boost::asio::error::no_descriptors)
            {
                log_error_ext(ec.message());
                continue;
            }
            else if(ec)
            {
                log_error_ext(ec.message());
                throw boost::system::system_error(ec);
            }
            start_init_session(std::move(m_http_socket), false);
        }
    }
}

void HttpTunnelServer::loop_https_accept(BSErrorCode ec)
{
    reenter(m_https_accept_co)
    {
        for(;;)
        {
            yield m_https_acceptor.async_accept(m_https_socket, [this](BSErrorCode ec) {
                this->loop_https_accept(ec);
            });
            if(ec == boost::asio::error::no_descriptors)
            {
                log_error_ext(ec.message());
                continue;
            }
            else if(ec)
            {
                log_error_ext(ec.message());
                throw boost::system::system_error(ec);
            }
            start_init_session(std::move(m_https_socket), true);
        }
    }
}

void HttpTunnelServer::loop_init_session(BSErrorCode ec, InitSessionInfoPtr co_info)
{
    reenter(co_info->co)
    {
        //非https连接
        if(!co_info->https)
        {
            yield http::async_read(co_info->socket, co_info->buffer, co_info->req, [co_info, this](const BSErrorCode& ec, std::size_t) {
                this->loop_init_session(ec, co_info);
            });
            if(ec)
            {
                log_warning_ext("loop_init_session failed, %1%", ec.message());
                return;
            }
            LogDebug << co_info->req;
            if(co_info->req.method() == http::verb::connect)
            {
                //为建立隧道请求
                {
                    auto id_it = co_info->req.find(SESSION_ID);
                    if(id_it != co_info->req.end())
                    {
                        co_info->session_id = (*id_it).value().to_string();
                    }
                }
                if(co_info->session_id.empty())
                {
                    log_error_ext("not has session id");
                    co_info->res.result(http::status::bad_request);
                    co_info->res.keep_alive(false);
                    co_info->res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
                    co_info->res.content_length(0);
                    yield http::async_write(co_info->socket, co_info->res, [co_info, this](const BSErrorCode& ec, std::size_t) {
                        this->loop_init_session(ec, co_info);
                    });
                    LogDebug << co_info->res;
                    return;
                }

                co_info->res.result(http::status::ok);
                co_info->res.version(11);
                co_info->res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
                co_info->res.content_length(0);
                co_info->res.keep_alive(true);

                yield http::async_write(co_info->socket, co_info->res, [co_info, this](const BSErrorCode& ec, std::size_t) {
                    this->loop_init_session(ec, co_info);
                });
                LogDebug << co_info->res;
                if(ec)
                {
                    log_warning_ext("loop_init_session failed, %1%", ec.message());
                    return;
                }
                add_tunnel_session(co_info);
                yield
                {
                    auto session = co_info->session.lock();
                    if(!session)
                    {
                        log_error_ext("lock to shared_ptr failed");
                        return;
                    }
                    session->async_run([this, co_info](BSErrorCode ec) {
                        this->loop_init_session(ec, co_info);
                    });
                }
                log_warning_ext("remove tunnel, err:%1%, session id:%2%", ec.message(), co_info->session_id);
                remove_tunnel_session(co_info->session_id, co_info->session.lock());
            }
            else
            {
                //为转发请求
                start_http_session(co_info);
            }
        }
        else
        {
            //https连接
            co_info->ssl_socket.reset(new SslSocket(std::move(co_info->socket), m_ssl_cxt));
            yield co_info->ssl_socket->async_handshake(boost::asio::ssl::stream_base::server, [this, co_info](BSErrorCode ec) {
                this->loop_init_session(ec, co_info);
            });
            if(ec)
            {
                log_warning_ext("loop_init_session failed, %1%", ec.message());
                return;
            }

            yield http::async_read(*(co_info->ssl_socket), co_info->buffer, co_info->req, [co_info, this](const BSErrorCode& ec, std::size_t) {
                this->loop_init_session(ec, co_info);
            });
            if(ec)
            {
                log_warning_ext("loop_init_session failed, %1%", ec.message());
                return;
            }
            LogDebug << co_info->req;
            if(co_info->req.method() == http::verb::connect)
            {
                //为建立隧道请求
                {
                    auto id_it = co_info->req.find(SESSION_ID);
                    if(id_it != co_info->req.end())
                    {
                        co_info->session_id = (*id_it).value().to_string();
                    }
                }
                if(co_info->session_id.empty())
                {
                    log_error_ext("not has session id");
                    co_info->res.result(http::status::bad_request);
                    co_info->res.keep_alive(false);
                    co_info->res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
                    co_info->res.content_length(0);
                    yield http::async_write(*(co_info->ssl_socket), co_info->res, [co_info, this](const BSErrorCode& ec, std::size_t) {
                        this->loop_init_session(ec, co_info);
                    });
                    LogDebug << co_info->res;
                    return;
                }

                co_info->res.result(http::status::ok);
                co_info->res.version(11);
                co_info->res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
                co_info->res.content_length(0);
                co_info->res.keep_alive(true);

                yield http::async_write(*(co_info->ssl_socket), co_info->res, [co_info, this](const BSErrorCode& ec, std::size_t) {
                    this->loop_init_session(ec, co_info);
                });
                LogDebug << co_info->res;
                if(ec)
                {
                    log_warning_ext("loop_init_session failed, %1%", ec.message());
                    return;
                }
                add_tunnel_session(co_info);
                yield
                {
                    auto session = co_info->session.lock();
                    if(!session)
                    {
                        log_error_ext("lock to shared_ptr failed");
                        return;
                    }
                    session->async_run([this, co_info](BSErrorCode ec) {
                        this->loop_init_session(ec, co_info);
                    });
                }
                log_warning_ext("remove tunnel, err:%1%, session id:%2%", ec.message(), co_info->session_id);
                remove_tunnel_session(co_info->session_id, co_info->session.lock());
            }
            else
            {
                //为转发请求
                start_http_session(co_info);
            }
        }
    }
}

void HttpTunnelServer::loop_http_session(BSErrorCode ec, HttpSessionInfoPtr co_info)
{
    reenter(co_info->co)
    {
        do
        {
            //请求已接收
            {
                auto id_it = co_info->req.find(SESSION_ID);
                if(id_it != co_info->req.end())
                {
                    co_info->session_id = (*id_it).value().to_string();
                }
            }
            if(co_info->session_id.empty())
            {
                log_error_ext("not has session id");
                set_response(co_info->req, http::status::bad_request, co_info->res);
                co_info->res.keep_alive(false);
                if(co_info->https)
                {
                    yield http::async_write(*(co_info->ssl_socket), co_info->res, [co_info, this](const BSErrorCode& ec, std::size_t) {
                        this->loop_http_session(ec, co_info);
                    });
                }
                else
                {
                    yield http::async_write(co_info->socket, co_info->res, [co_info, this](const BSErrorCode& ec, std::size_t) {
                        this->loop_http_session(ec, co_info);
                    });
                }
                LogDebug << co_info->res;
                return;
            }
            co_info->session = find_session(co_info->session_id);
            if(!co_info->session)
            {
                set_response(co_info->req, http::status::not_found, co_info->res);
                if(co_info->https)
                {
                    yield http::async_write(*(co_info->ssl_socket), co_info->res, [co_info, this](const BSErrorCode& ec, std::size_t) {
                        this->loop_http_session(ec, co_info);
                    });
                }
                else
                {
                    yield http::async_write(co_info->socket, co_info->res, [co_info, this](const BSErrorCode& ec, std::size_t) {
                        this->loop_http_session(ec, co_info);
                    });
                }
                LogDebug << co_info->res;
                if(ec)
                {
                    log_warning_ext(ec.message());
                    return;
                }
                if(co_info->res.need_eof())
                {
                    if(co_info->https)
                    {
                        co_info->ssl_socket->next_layer().shutdown(tcp::socket::shutdown_both, ec);
                    }
                    else
                    {
                        co_info->socket.shutdown(tcp::socket::shutdown_both, ec);
                    }
                    return;
                }
            }
            else
            {
                yield co_info->session->async_request(std::move(co_info->req), co_info->timeout, [co_info, this](StringResponse res) {
                    co_info->res = std::move(res);
                    this->loop_http_session({}, co_info);
                });

                co_info->session = nullptr;
                co_info->session_id.clear();

                if(co_info->https)
                {
                    yield http::async_write(*(co_info->ssl_socket), co_info->res, [co_info, this](const BSErrorCode& ec, std::size_t) {
                        this->loop_http_session(ec, co_info);
                    });
                }
                else
                {
                    yield http::async_write(co_info->socket, co_info->res, [co_info, this](const BSErrorCode& ec, std::size_t) {
                        this->loop_http_session(ec, co_info);
                    });
                }
                LogDebug << co_info->res;
                if(ec)
                {
                    log_error_ext("%1%, err:%2%", ec.value(), ec.message());
                    return;
                }

                if(co_info->res.need_eof())
                {
                    if(co_info->https)
                    {
                        co_info->ssl_socket->next_layer().shutdown(tcp::socket::shutdown_both, ec);
                    }
                    else
                    {
                        co_info->socket.shutdown(tcp::socket::shutdown_both, ec);
                    }
                    return;
                }
            }

            //读取一个请求
            if(co_info->https)
            {
                yield http::async_read(*(co_info->ssl_socket), co_info->buffer, co_info->req, [co_info, this](const BSErrorCode& ec, std::size_t) {
                    this->loop_http_session(ec, co_info);
                });
            }
            else
            {
                yield http::async_read(co_info->socket, co_info->buffer, co_info->req, [co_info, this](const BSErrorCode& ec, std::size_t) {
                    this->loop_http_session(ec, co_info);
                });
            }
            if(ec)
            {
                log_warning_ext("loop_http_session failed, %1%", ec.message());
                return;
            }
            LogDebug << co_info->req;
        } while(1);
    }
}

#include <boost/asio/unyield.hpp>

void HttpTunnelServer::set_response(const StringRequest& req, http::status s, StringResponse& res)
{
    res.result(s);
    res.version(req.version());
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.keep_alive(req.keep_alive());
    res.content_length(0);
}

void HttpTunnelServer::add_tunnel_session(InitSessionInfoPtr init_info)
{
    std::lock_guard<std::mutex> lk(m_mutex);
    auto session_it = m_sessions.find(init_info->session_id);
    if(session_it != m_sessions.end())
    {
        log_warning("already has session:%1%", init_info->session_id);
        session_it->second->cancel();
    }
    TunnelSessionPtr session;
    if(init_info->https)
    {
        session.reset(new HttpsTunnelSession(init_info->session_id, init_info->ssl_socket));
    }
    else
    {
        session.reset(new HttpTunnelSession(init_info->session_id, init_info->socket));
    }
    init_info->session = session;
    m_sessions[init_info->session_id] = session;
}

TunnelSessionPtr HttpTunnelServer::find_session(const string& session_id)
{
    std::lock_guard<std::mutex> lk(m_mutex);
    auto session_it = m_sessions.find(session_id);
    if(session_it == m_sessions.end())
    {
        log_error_ext("find_session,not find session:%1%", session_id);
        return nullptr;
    }
    return session_it->second;
}

void HttpTunnelServer::remove_tunnel_session(const string& session_id, TunnelSessionPtr session)
{
    std::lock_guard<std::mutex> lk(m_mutex);
    auto session_it = m_sessions.find(session_id);
    if(session_it == m_sessions.end())
    {
        return;
    }
    if(session_it->second.get() != session.get())
    {
        return;
    }
    m_sessions.erase(session_it);
}
