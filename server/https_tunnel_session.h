#ifndef HTTPS_TUNNEL_SESSION_H
#define HTTPS_TUNNEL_SESSION_H

#include "kconfig.h"
#include "tunnel_session.h"

class HttpsTunnelSession : public TunnelSession
{
public:
    HttpsTunnelSession(const string& session_id, std::shared_ptr<SslSocket> s);
    virtual ~HttpsTunnelSession();

    void async_run(RunCallback&& cb) override;
    void cancel() override;

    void async_request(StringRequest req, int timeout, RequestCallback&& cb) override;

protected:
    void loop_send(BSErrorCode ec);

    void loop_recv(BSErrorCode ec);

protected:
    std::shared_ptr<SslSocket> m_socket_ptr;
    SslSocket& m_socket;
    DTimer m_wait_send_timer;
};

#endif // HTTPS_TUNNEL_SESSION_H
