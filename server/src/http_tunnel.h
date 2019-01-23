#ifndef HTTP_TUNNEL_H
#define HTTP_TUNNEL_H

#include "kconfig.h"
class Manager;

typedef boost::fibers::promise<StrResponse> HttpPromise;

class HttpTunnel
{
public:
    HttpTunnel(TcpSocket &s);
    ~HttpTunnel();

    void start();

    //stop暂未实现
    void stop();

    StrResponse request(StrRequest& req);

private:
    void process_send_req();

    void process_recv_res();

private:
    TcpSocket m_socket;
    map<string, HttpPromise> m_http_promise;
    boost::fibers::mutex m_mutex;
    uint32_t m_tid = 1;

    typedef boost::fibers::unbuffered_channel<StrRequest> send_channel_t;
    send_channel_t m_send_channel;
    boost::fibers::fiber m_send_fiber;

    boost::fibers::fiber m_recv_fiber;
};

#endif // HTTP_TUNNEL_H
