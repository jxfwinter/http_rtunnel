#include "http_tunnel.h"
#include "manager.h"

#define TID "TID-J"

HttpTunnel::HttpTunnel(TcpSocket &s) :
    m_socket(std::move(s))
{

}

HttpTunnel::~HttpTunnel()
{

}

void HttpTunnel::start()
{
    boost::fibers::fiber fsend([this](){
        this->process_send_req();
    });

    m_send_fiber.swap(fsend);

    boost::fibers::fiber frecv([this](){
        this->process_recv_res();
    });

    m_recv_fiber.swap(frecv);

    m_send_fiber.join();
    m_recv_fiber.join();
}

void HttpTunnel::stop()
{

}

StrResponse HttpTunnel::request(StrRequest& req)
{
    StrResponse res;
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.keep_alive(req.keep_alive());

    boost::fibers::promise<StrResponse> promise;
    boost::fibers::future<StrResponse> future(promise.get_future());
    char tid[32];
    {
        std::lock_guard<boost::fibers::mutex> lk(m_mutex);
        sprintf(tid, "%d", m_tid);
        ++m_tid;
        m_http_promise[tid] = std::move(promise);
    }

    req.insert(TID, tid);

    boost::fibers::channel_op_status s = m_send_channel.push(std::move(req));
    if(s != boost::fibers::channel_op_status::success)
    {
        if(s != boost::fibers::channel_op_status::closed)
        {
            LogErrorExt << "send channel failed, status:" << static_cast<int>(s);
        }
        else
        {
            LogDebugExt << "send channel failed, status:" << static_cast<int>(s);
        }

        {
            std::lock_guard<boost::fibers::mutex> lk(m_mutex);
            auto it = m_http_promise.find(tid);
            if(it != m_http_promise.end())
            {
                res.result(http::status::connection_closed_without_response);
                it->second.set_value(std::move(res));
                m_http_promise.erase(it);
            }
        }
        return future.get();
    }

    //等待响应的超时时间
    boost::fibers::future_status fs = future.wait_for(std::chrono::seconds(m_timeout_seconds));
    if (fs == boost::fibers::future_status::timeout)
    {
        {
            std::lock_guard<boost::fibers::mutex> lk(m_mutex);
            auto it = m_http_promise.find(tid);
            if(it != m_http_promise.end())
            {
                res.result(http::status::request_timeout);
                it->second.set_value(std::move(res));
                m_http_promise.erase(it);
            }
        }
        return future.get();
    }
    return future.get();
}

void HttpTunnel::process_send_req()
{
    boost::fibers::future<boost::system::error_code> f;
    boost::system::error_code ec;
    StrRequest req;
    while(1)
    {
        boost::fibers::channel_op_status s = m_send_channel.pop(req);
        if(s != boost::fibers::channel_op_status::success)
        {
            if(s != boost::fibers::channel_op_status::closed)
            {
                LogErrorExt << "send pop failed, status:" << static_cast<int>(s);
            }
            else
            {
                LogDebugExt << "send pop failed, status:" << static_cast<int>(s);
            }
            break;
        }
        f = http::async_write(m_socket, req, boost::asio::fibers::use_future([](boost::system::error_code ec, size_t n) {
                                  return ec;
                              }));
        ec = f.get();
        if(ec)
        {
            LogErrorExt << ec.message();
            m_socket.shutdown(tcp::socket::shutdown_both, ec);
            break;
        }
    }
}

void HttpTunnel::process_recv_res()
{
    boost::system::error_code ec;
    StrResponse res;
    boost::beast::flat_buffer buffer;
    while(1)
    {
        f = http::async_read(socket, buffer, res, boost::asio::fibers::use_future([](boost::system::error_code ec, size_t) -> boost::system::error_code {
                                 return ec;
                             }));
        ec = f.get();
        if(ec)
        {
            LogErrorExt << ec.message();
            m_socket.shutdown(tcp::socket::shutdown_both, ec);
            break;
        }

        auto it = res.find(TID);
        if(it == res.end())
        {
            LogError << "TID not exist";
        }
        else
        {
            const string& tid = (*it).value();
            {
                std::lock_guard<boost::fibers::mutex> lk(m_mutex);
                auto msg_it = m_http_promise.find(id);
                if (msg_it != m_http_promise.end())
                {
                    res.erase(it);
                    msg_it->second.set_value(std::move(res));
                    m_http_promise.erase(msg_it);
                }
                else //已超时
                {
                    LogErrorExt << "can not find transtion msg, already timeout, TID:" << tid;
                }
            }
        }
    }
}
