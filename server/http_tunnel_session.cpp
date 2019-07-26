#include "http_tunnel_session.h"
#include "http_tunnel_server.h"

TMsgContext::TMsgContext(boost::asio::executor ex) : timer(ex)
{

}

HttpTunnelSession::HttpTunnelSession(TcpSocket &s, const string &session_id) :
    m_socket(std::move(s)), m_session_id(session_id), m_wait_send_timer(m_socket.get_executor())
{

}

HttpTunnelSession::~HttpTunnelSession()
{
    LogDebug << "~HttpTunnelSession, session_id:" << m_session_id;
}

void HttpTunnelSession::async_run(RunCallback&& cb)
{
    m_cb = std::move(cb);
    loop_send({});
    loop_recv({});
}

void HttpTunnelSession::async_request(StringRequest req, int timeout, RequestCallback&& cb)
{
    auto self(shared_from_this());
    string tid;
    {
        char tmp[32];
        std::lock_guard<std::mutex> lk(m_mutex);
        sprintf(tid, "%d", m_tid);
        ++m_tid;
        tid = tmp;
    }

    req.set(TID, tid);
    LogDebug << "tid:" << tid;
    TMsgContextPtr tmsg_cxt = std::make_shared<TMsgContext>(m_socket.get_executor());
    tmsg_cxt->req = std::move(req);
    tmsg_cxt->cb = std::move(cb);
    tmsg_cxt->tid = tid;

    tmsg_cxt->timer.expires_from_now(boost::posix_time::seconds(timeout));
    tmsg_cxt->timer.async_wait([tid, self, this](BSErrorCode ec){
        if(ec == boost::asio::error::operation_aborted)
        {
            return;
        }
        else
        {
            callback_by_timeout(tid);
        }
    });

    {
        std::lock_guard<std::mutex> lk(m_mutex);
        m_all_req_cxt.push_back(tmsg_cxt);
    }

    BSErrorCode ec;
    m_wait_send_timer.cancel(ec);
}

TMsgContextPtr HttpTunnelSession::get_non_send_tmsg()
{
    std::lock_guard<std::mutex> lk(m_mutex);
    for (auto it = m_all_req_cxt.cbegin(); it != m_all_req_cxt.cend(); ++it)
    {
        TMsgContextPtr& ptr = *it;
        bool sended = ptr->sended;
        if(!sended)
        {
            ptr->sended = true;
            return ptr;
        }
    }
    return nullptr;
}

void HttpTunnelSession::callback_by_timeout(const string& tid)
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
        cxt.res.result(http::status::request_timeout);
        cxt.cb(std::move(cxt.res));
    }
}

void HttpTunnelSession::callback_by_error(const string& tid, BSErrorCode ec)
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
        cxt.res.result(http::status::connection_closed_without_response);
        cxt.cb(std::move(cxt.res));
    }
}

void HttpTunnelSession::callback_by_recv_response(const string& tid, StringResponse res)
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
}

#include <boost/asio/yield.hpp>
void HttpTunnelSession::loop_send(BSErrorCode ec)
{
    auto self(shared_from_this());
    TMsgContextPtr msg_cxt;
    reenter(m_send_co)
    {
        for(;;)
        {
            m_wait_send_timer.expires_from_now(boost::posix_time::seconds(10));
            yield m_wait_send_timer.async_wait([self, this](BSErrorCode ec) {
                this->loop_send(ec);
            });
            if(!ec)
            {
                continue;
            }
            if(ec != boost::asio::error::operation_aborted)
            {
                return;
            }
            if(!m_socket.is_open())
            {
                return;
            }

            for(;;)
            {
                msg_cxt = get_non_send_tmsg();
                if(!msg_cxt)
                {
                    break;
                }
                m_cur_send_tid = msg_cxt->tid;
                yield http::async_write(m_socket, msg_cxt->req, [self, this](BSErrorCode ec, size_t) {
                    this->loop_send(ec);
                });
                if(ec)
                {
                    callback_by_error(m_cur_send_tid, ec);
                    return;
                }
            }
        }
    }
}

void HttpTunnelSession::loop_recv(BSErrorCode ec)
{
    auto self(shared_from_this());
    StringResponse::const_iterator it;
    reenter(m_recv_co)
    {
        for(;;)
        {
            m_recv_res = {};
            yield http::async_read(m_socket, m_recv_buffer, m_recv_res, [self, this](BSErrorCode ec, size_t) {
                this->loop_recv(ec);
            });
            if(ec)
            {
                log_error_ext(ec.message());
                m_socket.shutdown(tcp::socket::shutdown_both, ec);
                m_socket.close(ec);
                m_wait_send_timer.cancel(ec);
                m_cb(ec);
                return;
            }
            it = m_recv_res.find(TID);
            if(it == m_recv_res.end())
            {
                log_error_ext("TID not exist");
                continue;
            }
            callback_by_recv_response((*it).value().to_string(), std::move(m_recv_res));
        }
    }
}

#include <boost/asio/unyield.hpp>
