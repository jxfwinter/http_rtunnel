#ifndef WS_HTTP_SESSION_H
#define WS_HTTP_SESSION_H

#include "kconfig.h"
#include "ws_call_session.h"
class Manager;

class WSHttpSession : public WsCallSession
{
public:
    WSHttpSession(WsSessionContext& cxt, tcp::socket &s, Manager& svr);
    ~WSHttpSession();

protected:
    virtual bool is_allow(const WsSessionContext& cxt) override;
    virtual void on_close(const WsSessionContext& cxt) override;
    virtual void on_error(const WsSessionContext& cxt) override;

private:
    Manager& m_svr;
};

#endif // WS_HTTP_SESSION_H
