#include "tunnel_session.h"

TMsgContext::TMsgContext(boost::asio::executor ex) : timer(ex)
{

}

TunnelSession::TunnelSession(const string &session_id) :
    m_session_id(session_id)
{
}

TunnelSession::~TunnelSession()
{

}

TMsgContextPtr TunnelSession::get_non_send_tmsg()
{
    std::lock_guard<std::mutex> lk(m_mutex);
    for (auto it = m_all_req_cxt.cbegin(); it != m_all_req_cxt.cend(); ++it)
    {
        TMsgContextPtr ptr = *it;
        bool sended = ptr->sended;
        if(!sended)
        {
            ptr->sended = true;
            return ptr;
        }
    }
    return nullptr;
}

void TunnelSession::callback_by_timeout(const string& tid)
{
    TMsgContextPtr ptr;
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        for (auto it = m_all_req_cxt.begin(); it != m_all_req_cxt.end(); ++it)
        {
            if((*it)->tid == tid)
            {
                ptr = *it;
                m_all_req_cxt.erase(it);
                break;
            }
        }
    }
    if(ptr)
    {
        TMsgContext& cxt = *ptr;
        cxt.res.result(http::status::gateway_timeout);
        cxt.res.version(cxt.req.version());
        cxt.res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        cxt.res.keep_alive(cxt.req.keep_alive());
        cxt.cb(std::move(cxt.res));
    }
    else
    {
        log_warning_ext("can not find tid:%1%", tid);
    }
}

void TunnelSession::callback_by_error(const string& tid, BSErrorCode ec)
{
    TMsgContextPtr ptr;
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        for (auto it = m_all_req_cxt.begin(); it != m_all_req_cxt.end(); ++it)
        {
            if((*it)->tid == tid)
            {
                ptr = *it;
                m_all_req_cxt.erase(it);
                break;
            }
        }
    }
    if(ptr)
    {
        TMsgContext& cxt = *ptr;
        BSErrorCode ec;
        cxt.timer.cancel(ec);
        cxt.res.result(http::status::bad_gateway);
        cxt.res.version(cxt.req.version());
        cxt.res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        cxt.res.keep_alive(cxt.req.keep_alive());
        cxt.cb(std::move(cxt.res));
    }
    else
    {
        log_warning_ext("can not find tid:%1%", tid);
    }
}

void TunnelSession::callback_by_recv_response(const string& tid, StringResponse res)
{
    TMsgContextPtr ptr;
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        for (auto it = m_all_req_cxt.begin(); it != m_all_req_cxt.end(); ++it)
        {
            if((*it)->tid == tid)
            {
                ptr = *it;
                m_all_req_cxt.erase(it);
                break;
            }
        }
    }
    if(ptr)
    {
        TMsgContext& cxt = *ptr;
        BSErrorCode ec;
        cxt.timer.cancel(ec);
        cxt.res = std::move(res);
        cxt.cb(std::move(cxt.res));
    }
    else
    {
        log_warning_ext("can not find tid:%1%", tid);
    }
}
