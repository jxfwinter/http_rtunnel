#include "manager.h"
#include "ws_http_session.h"

Manager::Manager() :
    m_http_server(ConfigParams::instance().http_thread_pool, ConfigParams::instance().http_listen_addr, ConfigParams::instance().http_listen_port),
    m_ws_server(ConfigParams::instance().ws_thread_pool, ConfigParams::instance().ws_listen_addr, ConfigParams::instance().ws_listen_port)
{
    //初始化允许的url，不包含查询参数
    ConfigParams& cfg = ConfigParams::instance();
    for(auto& url : cfg.listen_urls)
    {
        m_url_token_session[url];
        m_http_server.resource["^" + url + "$"][http::verb::post] = [this](RequestContext& cxt) {
            this->process_http_req(cxt);
        };
    }

    m_ws_server.create_session = [this](WsSessionContext& cxt, tcp::socket& s) mutable
    {
        auto ses = WSHttpSessionPtr(new WSHttpSession(cxt, s, *this));
        return ses;
    };
}

Manager::~Manager()
{

}

void Manager::start()
{
    m_http_server.start();
    m_ws_server.start();
}

void Manager::stop()
{
    m_http_server.stop();
    m_ws_server.stop();
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
        string req_buffer = req_to_buffer(cxt.req);
        if(req_buffer.empty())
        {
            cxt.res.result(http::status::bad_request);
            return;
        }

        WSHttpSessionPtr session = find_session(cxt.path, token_it->second);
        if(!session)
        {
            cxt.res.result(http::status::not_found);
            return;
        }
        string res_buffer = session->send_call(std::move(req_buffer));
        cxt.res = buffer_to_res(res_buffer);
    }
    catch(std::exception& e)
    {
        LogErrorExt << e.what() << ",type:" << typeid(e).name();
        const boost::stacktrace::stacktrace *st = boost::get_error_info<traced>(e);
        if (st)
        {
            LogErrorExt << *st;
        }
        int error_code = 999999;
        const int *error = boost::get_error_info<global_error_code>(e);
        if (error)
        {
            error_code = *error;
            LogErrorExt << "error_code:" << error_code;
        }
        if(error_code == (int)WsCallError::NETWORK_ERROR)
        {
            cxt.res.result(http::status::connection_closed_without_response);
        }
        else if(error_code == (int)WsCallError::TIMEOUT)
        {
            cxt.res.result(http::status::request_timeout);
        }
        else
        {
            cxt.res.result(http::status::internal_server_error);
        }
    }
}

string Manager::req_to_buffer(StrRequest& req)
{
    boost::system::error_code ec;
    string sr_buf;
    size_t consume_size;
    http::request_serializer<http::string_body> sr(req);
    for(;;)
    {
        sr.next(ec, [&sr_buf, &consume_size](auto ec, auto buffers) {
               consume_size = boost::asio::buffer_size(buffers);
               for(boost::asio::const_buffer b : boost::beast::detail::buffers_range(buffers))
                   sr_buf.append(static_cast<char const*>(b.data()), b.size());
        });
        if(ec)
        {
            LogErrorExt << ec.message();
            return string();
        }
        sr.consume(consume_size);
        if(sr.is_done())
            break;
    }
    return std::move(sr_buf);
}

StrResponse Manager::buffer_to_res(const string& parser_buf)
{
    StrResponse res;
    boost::system::error_code ec;
    http::response_parser<http::string_body> parser;
    buffers_suffix<boost::asio::const_buffer> cb{boost::asio::buffer(parser_buf)};

    for(;;)
    {
        auto const used = parser.put(cb, ec);
        cb.consume(used);
        if(ec)
        {
            LogErrorExt << ec.message();
            res.result(http::status::expectation_failed);
            return std::move(res);
        }
        if(parser.need_eof() && buffer_size(cb) == 0)
        {
            parser.put_eof(ec);
            if(ec)
            {
                LogErrorExt << ec.message();
                res.result(http::status::expectation_failed);
                return std::move(res);
            }
        }
        if(parser.is_done())
            break;
    }
    return std::move(parser.release());
}

bool Manager::add_session(const string& url, const string& token, WSHttpSessionPtr session)
{
    fiber_lock lk(m_mutex);
    auto it_url = m_url_token_session.find(url);
    if(it_url == m_url_token_session.end())
    {
        LogError << "add_session,not find url:" << url;
        return false;
    }

    std::unordered_map<string, WSHttpSessionPtr>& token_sessions = it_url->second;

    auto session_it = token_sessions.find(token);
    if(session_it != token_sessions.end())
    {
        session_it->second->stop();
    }
    token_sessions["token"] = session;
    ++m_ws_session_count;
    return true;
}

WSHttpSessionPtr Manager::find_session(const string& url, const string& token)
{
    fiber_lock lk(m_mutex);
    auto it_url = m_url_token_session.find(url);
    if(it_url == m_url_token_session.end())
    {
        LogError << "add_session,not find url:" << url;
        return nullptr;
    }
    std::unordered_map<string, WSHttpSessionPtr>& token_sessions = it_url->second;

    auto session_it = token_sessions.find(token);
    if(session_it == it_url->second.end())
    {
        return nullptr;
    }
    return session_it->second;
}

void Manager::remove_session(const string& url, const string& token, WSHttpSessionPtr session)
{
    fiber_lock lk(m_mutex);
    auto it_url = m_url_token_session.find(url);
    if(it_url == m_url_token_session.end())
    {
        LogError << "add_session,not find url:" << url;
        return;
    }
    std::unordered_map<string, WSHttpSessionPtr>& token_sessions = it_url->second;
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
    --m_ws_session_count;
}
