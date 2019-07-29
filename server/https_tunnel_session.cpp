#include "https_tunnel_session.h"

HttpsTunnelSession::HttpsTunnelSession(const string &session_id, std::shared_ptr<SslSocket> s) :
    TunnelSession(session_id), m_socket_ptr(s), m_socket(*m_socket_ptr), m_wait_send_timer(m_socket.get_executor())
{
    BSErrorCode ec;
    m_remote_ep = m_socket.next_layer().remote_endpoint(ec);
    log_debug("HttpsTunnelSession create, session_id:%1%, ep:%2%", m_session_id, m_remote_ep);
}

HttpsTunnelSession::~HttpsTunnelSession()
{
    log_debug("~HttpsTunnelSession, session_id:%1%, ep:%2%", m_session_id, m_remote_ep);
}

void HttpsTunnelSession::async_run(RunCallback&& cb)
{
    m_cb = std::move(cb);
    loop_send({});
    loop_recv({});
}

void HttpsTunnelSession::cancel()
{
    log_warning("session:%1%,ep:%2% cancel", m_session_id, m_remote_ep);
    BSErrorCode ec;
    m_socket.next_layer().shutdown(tcp::socket::shutdown_both, ec);
    m_socket.next_layer().close(ec);
    m_wait_send_timer.cancel(ec);
}

void HttpsTunnelSession::async_request(StringRequest req, int timeout, RequestCallback&& cb)
{
    auto self(shared_from_this());
    string tid;
    {
        char tmp[32];
        std::lock_guard<std::mutex> lk(m_mutex);
        sprintf(tmp, "%d", m_tid);
        ++m_tid;
        tid = tmp;
    }

    req.set(TID, tid);
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

#include <boost/asio/yield.hpp>
void HttpsTunnelSession::loop_send(BSErrorCode ec)
{
    auto self(shared_from_this());
    TMsgContextPtr msg_cxt;
    reenter(m_send_co)
    {
        for(;;)
        {
            //log_debug("session:%1%,ep:%2% wait send timer start", m_session_id, m_remote_ep);
            m_wait_send_timer.expires_from_now(boost::posix_time::seconds(10));
            yield m_wait_send_timer.async_wait([self, this](BSErrorCode ec) {
                    this->loop_send(ec);
            });
            if(!ec && m_socket.next_layer().is_open())
            {
                continue;
            }
            if(ec != boost::asio::error::operation_aborted)
            {
                log_debug("session:%1%,ep:%2% err:%3%", m_session_id, m_remote_ep, ec.message());
                return;
            }
            else if(ec == boost::asio::error::operation_aborted) //表示有消息需要发送
            {
                log_debug("session:%1%,ep:%2% wait send timer aborted", m_session_id, m_remote_ep);
            }

            if(!m_socket.next_layer().is_open())
            {
                log_debug("session:%1%,ep:%2% socket is closed", m_session_id, m_remote_ep);
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
                log_debug("tunnel send req:\n%1%", msg_cxt->req);
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

void HttpsTunnelSession::loop_recv(BSErrorCode ec)
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
                log_error_ext("session:%1%,ep:%2% err:%3%", m_session_id, m_remote_ep, ec.message());
                m_socket.next_layer().shutdown(tcp::socket::shutdown_both, ec);
                m_socket.next_layer().close(ec);
                m_wait_send_timer.cancel(ec);
                m_cb(ec);
                return;
            }
            log_debug("session:%1%,ep:%2% tunnel recv res:\n%3%", m_session_id, m_remote_ep, m_recv_res);
            it = m_recv_res.find(TID);
            if(it == m_recv_res.end())
            {
                log_error_ext("session:%1%,ep:%2% TID not exist", m_session_id, m_remote_ep);
                continue;
            }
            m_recv_res.set(SESSION_ID, m_session_id);
            callback_by_recv_response((*it).value().to_string(), std::move(m_recv_res));
        }
    }
}

#include <boost/asio/unyield.hpp>
