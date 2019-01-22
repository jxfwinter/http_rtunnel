#ifndef HTTP_TUNNEL_H
#define HTTP_TUNNEL_H

#include "kconfig.h"
class Manager;

typedef boost::fibers::promise<StrResponse> HttpPromise;

class HttpTunnel
{
public:
    HttpTunnel(TcpSocket &s, Manager& svr);
    ~HttpTunnel();

    void start();
    void stop();

    StrResponse request(StrRequest& req);

private:
    TcpSocket m_socket;
    Manager& m_svr;
    map<string, HttpPromise> m_http_promise;

    typedef boost::fibers::unbuffered_channel<StrRequest> send_channel_t;
    send_channel_t m_send_channel;
    boost::fibers::fiber m_send_fiber;

    boost::fibers::fiber m_recv_fiber;
};

#endif // HTTP_TUNNEL_H
