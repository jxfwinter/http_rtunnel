#ifndef HTTP_TUNNEL_SESSION_H
#define HTTP_TUNNEL_SESSION_H

#include "kconfig.h"
#include "tunnel_session.h"

class HttpTunnelSession : public TunnelSession
{
public:
    HttpTunnelSession(const string& session_id, TcpSocket &s);
    virtual ~HttpTunnelSession();

    void async_run(RunCallback&& cb) override;
    void cancel() override;

    void async_request(StringRequest req, int timeout, RequestCallback&& cb) override;

protected:
    void loop_send(BSErrorCode ec);

    void loop_recv(BSErrorCode ec);

protected:
    TcpSocket m_socket;
    DTimer m_wait_send_timer;
};

#endif // HTTP_TUNNEL_SESSION_H
