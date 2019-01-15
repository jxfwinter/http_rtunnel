#include "ws_http_session.h"
#include <ctime>
#include <chrono>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>

#define KK_PRT(fmt...)   \
    do {\
    time_t timep;\
    time(&timep);\
    tm* tt = localtime(&timep); \
    printf("[%d-%02d-%02d %02d:%02d:%02d][%s]-%d: ", tt->tm_year+1900,tt->tm_mon+1,tt->tm_mday,tt->tm_hour,tt->tm_min,tt->tm_sec, __FUNCTION__, __LINE__);\
    printf(fmt);\
    printf("\n");\
    }while(0)

static void set_socket_opt(const TcpSocket& socket)
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

WSHttpSession::WSHttpSession(IoContext& ioc) :
    m_ioc(ioc), m_timer(m_ioc), m_ws_stream(m_ioc)
{

}

WSHttpSession::~WSHttpSession()
{

}

void WSHttpSession::start(string host, uint16_t port, string target)
{
    m_send_queue.clear();
    m_host = std::move(host);
    m_port = port;
    m_target = std::move(target);

    start_resolve_co();
    start_check_timer();
}

void WSHttpSession::stop()
{
    m_send_queue.clear();
    stop_check_timer();
}

void WSHttpSession::start_resolve_co()
{
    m_resolve_co = Coroutine();
    m_resolver.reset(new Resolver(m_ioc));
    loop_resolve({}, {});
}

void WSHttpSession::start_conn_co()
{
    m_conn_co = Coroutine();
    if(m_ws_stream.next_layer().is_open())
    {
        boost::system::error_code ec;
        m_ws_stream.next_layer().close(ec);
    }
    loop_conn({});
}

void WSHttpSession::start_ws_recv_co()
{
    m_recv_co = Coroutine();
    loop_recv({});
}

void WSHttpSession::start_http_co(string id, string req_buf)
{
    HttpCoInfoPtr co_info(new HttpCoInfo(m_ioc));
    co_info->id = std::move(id);
    co_info->req_buffer = std::move(req_buf);

    loop_http({}, 0, std::move(co_info));
}

void WSHttpSession::start_ws_send_res(HttpCoInfoPtr co_info)
{
    //r表示响应
    string send_buffer;
    send_buffer.append("r");
    send_buffer.append(co_info->id);
    send_buffer.append(co_info->res_buffer);
    bool write_in_progress = !m_send_queue.empty();
    m_send_queue.push_back(std::move(send_buffer));
    if (!write_in_progress)
    {
        m_send_co = Coroutine();
        loop_send({});
    }
}

void WSHttpSession::start_check_timer()
{
    m_timer_co = Coroutine();
    loop_check({});
}

void WSHttpSession::stop_check_timer()
{
    m_timer.cancel();
}

#include <boost/asio/yield.hpp>
void WSHttpSession::loop_resolve(boost::system::error_code ec, ResolverResult r)
{
    reenter(m_resolve_co)
    {
        m_socket_status = Resolving;
        KK_PRT("start resolve");
        yield m_resolver->async_resolve(Endpoint{address::from_string(m_host), m_port}, [this](boost::system::error_code ec, ResolverResult r) {
            this->loop_resolve(ec, r);
        });
        if(ec)
        {
            KK_PRT("error:%d,%s", ec.value(), ec.message().c_str());
            m_socket_status = Disconnected;
            yield break;
        }
        m_resolve_result = std::move(r);
        start_conn_co();
    }
}

void WSHttpSession::loop_conn(boost::system::error_code ec)
{
    reenter(m_conn_co)
    {
        m_socket_status = Connecting;
        KK_PRT("start conn");
        yield m_ws_stream.next_layer().async_connect((*m_resolve_result.begin()).endpoint(), [this](boost::system::error_code ec) {
            this->loop_conn(ec);
        });
        if(ec)
        {
            KK_PRT("error:%d,%s", ec.value(), ec.message().c_str());
            m_socket_status = Disconnected;
            yield break;
        }
        KK_PRT("start handshake");
        yield m_ws_stream.async_handshake(m_host, m_target, [this](boost::system::error_code ec) {
            this->loop_conn(ec);
        });
        if(ec)
        {
            KK_PRT("error:%d,%s", ec.value(), ec.message().c_str());
            m_ws_stream.next_layer().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
            m_socket_status = Disconnected;
            yield break;
        }
        set_socket_opt(m_ws_stream.next_layer());
        m_ws_stream.binary(true);
        m_socket_status = Connected;
        if(m_conn_cb)
        {
            m_conn_cb(m_socket_status);
        }
        start_ws_recv_co();
    }
}

void WSHttpSession::loop_recv(boost::system::error_code ec)
{
    reenter(m_recv_co)
    {
        while(1)
        {
            m_read_buffer.consume(m_read_buffer.size());
            yield m_ws_stream.async_read(m_read_buffer, [this](boost::system::error_code ec, size_t bytes_transferred) {
                this->loop_recv(ec);
            });
            if(ec)
            {
                KK_PRT("error:%d,%s", ec.value(), ec.message().c_str());
                if(m_socket_status != Disconnected)
                {
                    m_socket_status = Disconnected;
                    if(m_conn_cb)
                    {
                        m_conn_cb(m_socket_status);
                    }
                }
                yield break;
            }
            //检查消息体是否合法
            if(m_read_buffer.size() <= 5)
            {
                KK_PRT("buffer size small than 5");
                m_ws_stream.next_layer().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
                if(m_socket_status != Disconnected)
                {
                    m_socket_status = Disconnected;
                    if(m_conn_cb)
                    {
                        m_conn_cb(m_socket_status);
                    }
                }
                yield break;
            }
            //解析消息体
            const char* data = (char*)m_read_buffer.data().data();
            char msg_type = data[0];
            string id(&data[1], 4);

            //只支持请求
            if(msg_type != 's')
            {
                KK_PRT("error msg");
                continue;
            }
            //请求
            string req_buffer(&data[5], m_read_buffer.size() - 5);
            start_http_co(std::move(id), std::move(req_buffer));
        }
    }
}

void WSHttpSession::loop_http(boost::system::error_code ec, size_t bytes_transferred, HttpCoInfoPtr co_info)
{
    reenter(co_info->http_co)
    {
        yield co_info->http_socket.async_connect(Endpoint{address::from_string(m_local_ip), m_local_port}, [co_info, this](boost::system::error_code ec) {
            this->loop_http(ec, 0, co_info);
        });
        if(ec)
        {
            KK_PRT("error:%d,%s", ec.value(), ec.message().c_str());
            co_info->res_buffer = "HTTP/1.1 444 Connection Closed Without Response\r\n"
                                  "Connection: close\r\n"
                                  "\r\n";
            start_ws_send_res(co_info);
            yield break;
        }
        yield boost::asio::async_write(co_info->http_socket,
                                       boost::asio::buffer(co_info->req_buffer),
                                       [co_info, this](boost::system::error_code ec, size_t bytes_transferred){
            this->loop_http(ec, 0, co_info);
        });
        if(ec)
        {
            KK_PRT("error:%d,%s", ec.value(), ec.message().c_str());
            co_info->res_buffer = "HTTP/1.1 444 Connection Closed Without Response\r\n"
                                  "Connection: close\r\n"
                                  "\r\n";
            start_ws_send_res(co_info);
            yield break;
        }
        while(1)
        {
            yield boost::asio::async_read(co_info->http_socket,
                                          boost::asio::buffer(co_info->read_buf, sizeof(co_info->read_buf)),
                                          [co_info, this](boost::system::error_code ec, size_t bytes_transferred) {
                this->loop_http(ec, bytes_transferred, co_info);
            });

            if(ec && ec != boost::asio::error::eof)
            {
                //发生网络错误
                KK_PRT("error:%d,%s", ec.value(), ec.message().c_str());
                co_info->res_buffer = "HTTP/1.1 444 Connection Closed Without Response\r\n"
                                      "Connection: close\r\n"
                                      "\r\n";
                start_ws_send_res(co_info);
                yield break;
            }
            else if(ec == boost::asio::error::eof)
            {
                //连接正常结束
                if(bytes_transferred > 0)
                {
                    co_info->res_buffer.append(co_info->read_buf, bytes_transferred);
                }
                start_ws_send_res(co_info);
                yield break;
            }
            else
            {
                //读取中
                co_info->res_buffer.append(co_info->read_buf, bytes_transferred);
            }
        }
    }
}

void WSHttpSession::loop_send(boost::system::error_code ec)
{
    reenter(m_send_co)
    {
        while(!m_send_queue.empty())
        {
            yield
            {
                string& buffer = m_send_queue.front();
                m_ws_stream.async_write(boost::asio::buffer(buffer), [this](boost::system::error_code ec, std::size_t bytes_transferred) {
                    this->loop_send(ec);
                });
            }

            m_send_queue.pop_front();
            if(ec)
            {
                KK_PRT("error:%d,%s", ec.value(), ec.message().c_str());
                if(m_socket_status != Disconnected)
                {
                    m_socket_status = Disconnected;
                    if(m_conn_cb)
                    {
                        m_conn_cb(m_socket_status);
                    }
                }
                yield break;
            }
        }
    }
}

void WSHttpSession::loop_check(boost::system::error_code ec)
{
    reenter(m_timer_co)
    {
        while(1)
        {
            if(ec)
            {
                yield break;
            }

            if(m_socket_status == Disconnected)
            {
                start_resolve_co();
            }

            m_timer->expires_after(std::chrono::seconds(30));
            yield m_timer->async_wait([this](boost::system::error_code ec) {
                this->loop_check(ec);
            });
        }
    }
}

#include <boost/asio/unyield.hpp>
