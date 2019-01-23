#include "manager.h"
#include "http_tunnel.h"

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
        KK_PRT("setsockopt SO_KEEPALIVE failed");
    }
    ret = setsockopt(socket.native_handle(), IPPROTO_TCP, TCP_KEEPIDLE, &tcp_keepalive_time, sizeof(tcp_keepalive_time));
    if(ret < 0)
    {
        KK_PRT("setsockopt TCP_KEEPIDLE failed");
    }
    ret = setsockopt(socket.native_handle(), IPPROTO_TCP, TCP_KEEPINTVL, &tcp_keepalive_intvl, sizeof(tcp_keepalive_intvl));
    if(ret < 0)
    {
        KK_PRT("setsockopt TCP_KEEPINTVL failed");
    }
    ret = setsockopt(socket.native_handle(), IPPROTO_TCP, TCP_KEEPCNT, &tcp_keepalive_probes, sizeof(tcp_keepalive_probes));
    if(ret < 0)
    {
        KK_PRT("setsockopt TCP_KEEPCNT failed");
    }
}

Manager::Manager() :
    m_http_server(ConfigParams::instance().http_thread_pool, ConfigParams::instance().http_listen_addr, ConfigParams::instance().http_listen_port),
    m_work(new io_context_work(m_io_cxt.get_executor())), m_acceptoror(m_io_cxt), m_socket(m_io_cxt)
{
    m_listen_ep = tcp::endpoint{boost::asio::ip::make_address(ConfigParams::instance().tunnel_listen_addr),
            ConfigParams::instance().tunnel_listen_port};

    m_thread_count = ConfigParams::instance().tunnel_thread_pool;

    //初始化允许的url，不包含查询参数
    ConfigParams& cfg = ConfigParams::instance();
    for(auto& url : cfg.listen_urls)
    {
        m_url_token_session[url];
        m_http_server.resource["^" + url + "$"][http::verb::post] = [this](RequestContext& cxt) {
            this->process_http_req(cxt);
        };
    }
}

Manager::~Manager()
{

}

void Manager::start()
{
    m_http_server.start();
    m_io_cxt.restart();

    m_acceptor_fiber = boost::fibers::fiber([this](){
        this->accept();
    });
    for(int i=0; i<m_thread_count; ++i)
    {
        std::thread t([this]() {
            m_io_cxt.run();
        });
        m_threads.push_back(std::move(t));
    }
}

void Manager::stop()
{
    m_http_server.stop();
    boost::system::error_code ec;
    m_acceptor.close(ec);
    if(m_acceptor_fiber.joinable())
    {
        m_acceptor_fiber.join();
    }

    m_io_cxt.stop();
    for(int i=0; i<m_thread_count; ++i)
    {
        m_threads[i].join();
    }
}

void Manager::process_http_req(RequestContext& cxt)
{
    try
    {
        auto token_it = cxt.query_params.find("token");
        if(token_it == cxt.query_params.end())
        {
            cxt.res.result(http::status::bad_request);
            return;
        }
        //将请求转变为短连接
        bool old_keep_alive = cxt.req.keep_alive();
        cxt.req.keep_alive(false);

        HttpTunnelPtr session = find_session(cxt.path, token_it->second);
        if(!session)
        {
            cxt.res.result(http::status::not_found);
            return;
        }
        cxt.res = session->request(cxt.req);
        //将响应keep_alive恢复
        cxt.res.keep_alive(old_keep_alive);
    }
    catch(std::exception& e)
    {
        LogErrorExt << e.what() << ",type:" << typeid(e).name();
        cxt.res.result(http::status::internal_server_error);

        //        const boost::stacktrace::stacktrace *st = boost::get_error_info<traced>(e);
        //        if (st)
        //        {
        //            LogErrorExt << *st;
        //        }
        //        int error_code = 999999;
        //        const int *error = boost::get_error_info<global_error_code>(e);
        //        if (error)
        //        {
        //            error_code = *error;
        //            LogErrorExt << "error_code:" << error_code;
        //        }
        //        if(error_code == (int)WsCallError::NETWORK_ERROR)
        //        {
        //            cxt.res.result(http::status::connection_closed_without_response);
        //        }
        //        else if(error_code == (int)WsCallError::TIMEOUT)
        //        {
        //            cxt.res.result(http::status::request_timeout);
        //        }
        //        else
        //        {
        //            cxt.res.result(http::status::internal_server_error);
        //        }
    }
}

//string Manager::req_to_buffer(StrRequest& req)
//{
//    boost::system::error_code ec;
//    string sr_buf;
//    size_t consume_size;
//    http::request_serializer<http::string_body> sr(req);
//    for(;;)
//    {
//        sr.next(ec, [&sr_buf, &consume_size](auto ec, auto buffers) {
//               consume_size = boost::asio::buffer_size(buffers);
//               for(boost::asio::const_buffer b : boost::beast::detail::buffers_range(buffers))
//                   sr_buf.append(static_cast<char const*>(b.data()), b.size());
//        });
//        if(ec)
//        {
//            LogErrorExt << ec.message();
//            return string();
//        }
//        sr.consume(consume_size);
//        if(sr.is_done())
//            break;
//    }
//    return std::move(sr_buf);
//}

//StrResponse Manager::buffer_to_res(const string& parser_buf)
//{
//    StrResponse res;
//    boost::system::error_code ec;
//    http::response_parser<http::string_body> parser;
//    buffers_suffix<boost::asio::const_buffer> cb{boost::asio::buffer(parser_buf)};

//    for(;;)
//    {
//        auto const used = parser.put(cb, ec);
//        cb.consume(used);
//        if(ec)
//        {
//            LogErrorExt << ec.message();
//            res.result(http::status::expectation_failed);
//            return std::move(res);
//        }
//        if(parser.need_eof() && buffer_size(cb) == 0)
//        {
//            parser.put_eof(ec);
//            if(ec)
//            {
//                LogErrorExt << ec.message();
//                res.result(http::status::expectation_failed);
//                return std::move(res);
//            }
//        }
//        if(parser.is_done())
//            break;
//    }
//    return std::move(parser.release());
//}

void Manager::accept()
{
    try
    {
        m_acceptor.open(m_listen_ep.protocol());
        m_acceptor.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
        m_acceptor.bind(m_listen_ep);
        m_acceptor.listen();

        boost::fibers::future<boost::system::error_code> f;
        boost::system::error_code ec;
        for (;;)
        {
            f = m_acceptor.async_accept(m_socket,
                                        boost::asio::fibers::use_future([](boost::system::error_code ec){
                                            return ec;
                                        }));
            ec = f.get();
            if (ec)
            {
                if(ec.value() == boost::asio::error::no_descriptors)
                {
                    LogErrorExt << ec.message();
                    continue;
                }
                else if(ec.value() == boost::asio::error::operation_aborted) //主动关闭结束
                {
                    LogWarnExt << ec.message();
                    break;
                }
                else
                {
                    throw_with_trace(boost::system::system_error(ec)); //some other error
                }
            }
            else
            {
                boost::fibers::fiber([socket = std::move(m_socket), this]() mutable {
                    boost::fibers::future<boost::system::error_code> f;
                    boost::system::error_code ec;
                    boost::beast::flat_buffer buffer;

                    try
                    {
                        StrRequest req;
                        f = http::async_read(socket, buffer, req, boost::asio::fibers::use_future([](boost::system::error_code ec, size_t) -> boost::system::error_code {
                                                 return ec;
                                             }));
                        ec = f.get();
                        if(ec)
                        {
                            LogErrorExt << ec.message();
                            return;
                        }
                        auto const send_bad_request =
                                [&req, &socket, &f, &ec](boost::beast::string_view why)
                        {
                            StrResponse res{http::status::bad_request, req.version()};
                            //res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
                            res.set(http::field::content_type, "text/html");
                            res.keep_alive(req.keep_alive());
                            res.body() = why.to_string();
                            res.prepare_payload();
                            f = http::async_write(socket, res, boost::asio::fibers::use_future([](boost::system::error_code ec, size_t n) {
                                                      return ec;
                                                  }));
                            ec = f.get();
                            if(ec)
                            {
                                LogErrorExt << ec.message();
                                socket.shutdown(tcp::socket::shutdown_both, ec);
                                return;
                            }
                            socket.shutdown(tcp::socket::shutdown_both, ec);
                        };

                        //难证是否为代理请求
                        auto setup_it = req.find(SETUP_MARK);
                        if(setup_it == req.end())
                        {
                            LogError << "not setup request";
                            return send_bad_request("not setup request");
                        }

                        string query_string;
                        string path;
                        if(!kkurl::parse_target(req.target(), path, query_string))
                        {
                            LogError << "parse target error," << req.target();
                            return send_bad_request("parse target error");
                        }
                        //验证url合法性
                        auto it_url = m_url_token_session.find(path);
                        if(it_url == m_url_token_session.end())
                        {
                            LogError << "add_session,not find url:" << path;
                            return send_bad_request("parse target error");
                        }


                        CaseInsensitiveMultimap query_params = kkurl::parse_query_string(query_string);
                        auto it_token = query_params.find("token");
                        if(it_token == query_params.end())
                        {
                            LogError << "not has token," << req.target();
                            return send_bad_request("not has token");
                        }

                        http::response<http::empty_body> res{http::status::ok, req.version()};
                        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
                        res.keep_alive(req.keep_alive());
                        f = http::async_write(socket, res, boost::asio::fibers::use_future([](boost::system::error_code ec, size_t n) {
                                                  return ec;
                                              }));
                        ec = f.get();
                        if(ec)
                        {
                            LogErrorExt << ec.message();
                            socket.shutdown(tcp::socket::shutdown_both, ec);
                            return;
                        }
                        set_socket_opt(socket);
                        HttpTunnelPtr tunnel = std::make_shared<HttpTunnel>(socket, *this);
                        add_session(path, it_token->second, tunnel);

                        try
                        {
                            //等待结束
                            tunnel->start();
                        }
                        catch (std::exception const &e)
                        {
                            LogErrorExt << e.what() << "," << typeid(e).name();
                        }

                        remove_session(path, it_token->second, tunnel);
                    }
                    catch (std::exception const &e)
                    {
                        LogErrorExt << e.what() << "," << typeid(e).name();
                    }
                }).detach();
            }
        }
    }
    catch (std::exception const &e)
    {
        LogErrorExt << e.what() << "," << typeid(e).name();
        throw e;
    }
}

bool Manager::add_session(const string& url, const string& token, HttpTunnelPtr session)
{
    fiber_lock lk(m_mutex);
    std::unordered_map<string, HttpTunnelPtr>& token_sessions = m_url_token_session[url];

    auto session_it = token_sessions.find(token);
    if(session_it != token_sessions.end())
    {
        session_it->second->stop();
    }
    token_sessions["token"] = session;
    ++m_tunnel_count;
    return true;
}

HttpTunnelPtr Manager::find_session(const string& url, const string& token)
{
    fiber_lock lk(m_mutex);
    auto it_url = m_url_token_session.find(url);
    if(it_url == m_url_token_session.end())
    {
        LogError << "add_session,not find url:" << url;
        return nullptr;
    }
    std::unordered_map<string, HttpTunnelPtr>& token_sessions = it_url->second;

    auto session_it = token_sessions.find(token);
    if(session_it == it_url->second.end())
    {
        return nullptr;
    }
    return session_it->second;
}

void Manager::remove_session(const string& url, const string& token, HttpTunnelPtr session)
{
    fiber_lock lk(m_mutex);
    auto it_url = m_url_token_session.find(url);
    if(it_url == m_url_token_session.end())
    {
        LogError << "add_session,not find url:" << url;
        return;
    }
    std::unordered_map<string, HttpTunnelPtr>& token_sessions = it_url->second;
    auto session_it = token_sessions.find(token);
    if(session_it == it_url->second.end())
    {
        return;
    }
    if(session_it->second.get() != session.get())
    {
        return;
    }
    token_sessions.erase(session_it);
    --m_tunnel_count;
}
