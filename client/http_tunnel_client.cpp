#include "http_tunnel_client.h"
#include <ctime>
#include <chrono>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <iostream>
#include "pub.h"

#define KK_PRT(fmt...)   \
    do {\
    time_t timep;\
    time(&timep);\
    tm* tt = localtime(&timep); \
    printf("[%d-%02d-%02d %02d:%02d:%02d][%s]-%d: ", tt->tm_year+1900,tt->tm_mon+1,tt->tm_mday,tt->tm_hour,tt->tm_min,tt->tm_sec, __FUNCTION__, __LINE__);\
    printf(fmt);\
    printf("\n");\
    }while(0)

HttpTunnelClient::HttpTunnelClient(IoContext& ioc) :
    m_ioc(ioc), m_timer(m_ioc), m_socket(m_ioc), m_resolver(m_ioc)
{

}

HttpTunnelClient::~HttpTunnelClient()
{

}

void HttpTunnelClient::async_run(string host, uint16_t port, string session_id,
               string local_ip, uint16_t local_port,
               ConnectStatusNotify cb)
{
    m_host = std::move(host);
    m_port = port;
    m_session_id = std::move(session_id);

    m_local_ip = std::move(local_ip);
    m_local_port = local_port;
    m_conn_notify_cb = std::move(cb);

    m_running = true;
    loop_run({});
}

void HttpTunnelClient::cancel()
{
    m_running = false;
    boost::system::error_code ec;
    m_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
}

void HttpTunnelClient::start_http_co(string id, StrRequest& req)
{
    HttpCoInfoPtr co_info(new HttpCoInfo(m_ioc));
    co_info->id = std::move(id);
    co_info->req = std::move(req);

    loop_http({}, std::move(co_info));
}

void HttpTunnelClient::start_send_co(HttpCoInfoPtr co_info)
{
    //r表示响应
    bool write_in_progress = !m_send_response_queue.empty();
    m_send_response_queue.push_back(std::move(co_info->res));
    if (!write_in_progress)
    {
        m_send_co = Coroutine();
        loop_send({});
    }
}

#include <boost/asio/yield.hpp>
void HttpTunnelClient::loop_run(boost::system::error_code ec)
{
    auto self(shared_from_this());
    reenter(m_co)
    {
        while(m_running)
        {
            //连接
            m_send_response_queue.clear();
            while(m_running)
            {
                m_socket_status = Resolving;
                KK_PRT("start resolve");
                yield m_resolver.async_resolve(m_host, "", [self, this](boost::system::error_code ec, ResolverResult r) {
                    if(!ec)
                    {
                        m_resolve_result = std::move(r);
                    }
                    this->loop_run(ec);
                });
                if(ec)
                {
                    KK_PRT("error:%d,%s", ec.value(), ec.message().c_str());
                    m_socket_status = Disconnected;
                    m_timer.expires_after(std::chrono::seconds(2));
                    yield m_timer.async_wait([self, this](boost::system::error_code ec) {
                        this->loop_run(ec);
                    });
                    continue;
                }
                m_socket_status = Connecting;
                yield
                {
                    Endpoint ep = (*m_resolve_result.begin()).endpoint();
                    ep.port(m_port);
                    m_socket.async_connect(ep, [self, this](boost::system::error_code ec) {
                        this->loop_run(ec);
                    });
                }
                if(ec)
                {
                    KK_PRT("session_id:%s, err:%s", m_session_id.c_str(), ec.message().c_str());
                    m_socket_status = Disconnected;
                    m_timer.expires_after(std::chrono::seconds(30));
                    yield m_timer.async_wait([self, this](boost::system::error_code ec) {
                        this->loop_run(ec);
                    });
                    continue;
                }
                set_socket_opt(m_socket);
                break;
            } //连接

            //建立隧道
            //请求
            m_req = {};
            m_req.method(http::verb::connect);
            m_req.keep_alive(true);
            m_req.set(SESSION_ID, m_session_id);
            m_req.target("setup.tunnel");
            m_req.content_length(0);
            KK_PRT("start setup");
            yield http::async_write(m_socket, m_req, [self, this](boost::system::error_code ec, size_t) {
                this->loop_run(ec);
            });
            if(ec)
            {
                KK_PRT("error:%d,%s", ec.value(), ec.message().c_str());
                m_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
                if(m_socket.is_open())
                {
                    m_socket.close();
                }
                m_socket_status = Disconnected;
                continue;
            }
            //响应
            yield http::async_read(m_socket, m_read_buffer, m_res, [self, this](boost::system::error_code ec, size_t) {
                this->loop_run(ec);
            });
            if(ec)
            {
                KK_PRT("error:%d,%s", ec.value(), ec.message().c_str());
                m_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
                if(m_socket.is_open())
                {
                    m_socket.close();
                }
                m_socket_status = Disconnected;
                continue;
            }
            {
                if((int)m_res.result() >= 300 || (int)m_res.result() < 200)
                {
                    KK_PRT("setup error:%d", (int)m_res.result());
                    m_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
                    if(m_socket.is_open())
                    {
                        m_socket.close();
                    }
                    m_socket_status = Disconnected;
                    continue;
                }
            }

            m_socket_status = Connected;
            KK_PRT("setup success");
            if(m_conn_notify_cb)
            {
                m_conn_notify_cb(m_socket_status);
            }

            //开始接收http请求
            while(m_running)
            {
                yield http::async_read(m_socket, m_read_buffer, m_req, [self, this](boost::system::error_code ec, size_t) {
                    this->loop_run(ec);
                });
                if(ec)
                {
                    KK_PRT("error:%d,%s", ec.value(), ec.message().c_str());
                    m_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
                    if(m_socket.is_open())
                    {
                        m_socket.close();
                    }
                    m_socket_status = Disconnected;
                    if(m_conn_notify_cb)
                    {
                        m_conn_notify_cb(m_socket_status);
                    }
                    break;
                }
                std::cout << "recv req:" << m_req << "\n";
                //检查请求是否合法
                {
                    auto it = m_req.find(TID);
                    if(it == m_req.end())
                    {
                        KK_PRT("tid not exist");
                        continue;
                    }
                    else
                    {
                        //请求
                        boost::string_view tid = (*it).value();
                        m_req.erase(it);
                        start_http_co(tid.to_string(), m_req);
                    }
                }
            } //接收请求循环

        } //主循环
    }
}

void HttpTunnelClient::loop_http(boost::system::error_code ec, HttpCoInfoPtr co_info)
{
    auto self(shared_from_this());
    reenter(co_info->http_co)
    {
        yield co_info->http_socket.async_connect(Endpoint{boost::asio::ip::make_address(m_local_ip, ec), m_local_port}, [co_info, self, this](boost::system::error_code ec) {
            this->loop_http(ec, co_info);
        });
        if(ec)
        {
            KK_PRT("error:%d,%s", ec.value(), ec.message().c_str());
            co_info->res.result(http::status::service_unavailable);
            co_info->res.set(TID, co_info->id);
            start_send_co(co_info);
            yield break;
        }
        //使用短连接
        co_info->req.keep_alive(false);
        co_info->req.content_length(co_info->req.body().size());
        std::cout << "send req: " << co_info->req << "\n";
        yield http::async_write(co_info->http_socket, co_info->req, [co_info, self, this](boost::system::error_code ec, size_t){
            this->loop_http(ec, co_info);
        });
        if(ec)
        {
            KK_PRT("error:%d,%s", ec.value(), ec.message().c_str());
            co_info->res.result(http::status::service_unavailable);
            co_info->res.set(TID, co_info->id);
            start_send_co(co_info);
            yield break;
        }
        yield http::async_read(co_info->http_socket, co_info->buffer, co_info->res, [co_info, self, this](boost::system::error_code ec, size_t){
            this->loop_http(ec, co_info);
        });
        if(ec)
        {
            KK_PRT("error:%d,%s", ec.value(), ec.message().c_str());
            co_info->res.result(http::status::service_unavailable);
            co_info->res.set(TID, co_info->id);
            start_send_co(co_info);
            yield break;
        }
        co_info->res.set(TID, co_info->id);
        std::cout << "recv res: " << co_info->res << "\n";
        start_send_co(co_info);
    }
}

void HttpTunnelClient::loop_send(boost::system::error_code ec)
{
    auto self(shared_from_this());
    reenter(m_send_co)
    {
        while(!m_send_response_queue.empty())
        {
            yield
            {
                StrResponse& res = m_send_response_queue.front();
                //转换成长连接
                res.keep_alive(true);
                res.content_length(res.body().size());
                std::cout << "send res:" << res << "\n";
                http::async_write(m_socket, res, [self, this](boost::system::error_code ec, std::size_t) {
                    this->loop_send(ec);
                });
            }
            //不管是否成功,总是删除
            m_send_response_queue.pop_front();
            if(ec)
            {
                KK_PRT("error:%d,%s", ec.value(), ec.message().c_str());
                m_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
                yield break;
            }
        }
    }
}

#include <boost/asio/unyield.hpp>
