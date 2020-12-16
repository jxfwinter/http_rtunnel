#ifndef TUNNEL_SESSION_H
#define TUNNEL_SESSION_H

#include "kconfig.h"

typedef std::function<void (StringResponse)> RequestCallback;

typedef std::function<void (BSErrorCode)> RunCallback;

struct TMsgContext
{
    string tid;
    StringRequest req;
    StringResponse res;
    RequestCallback cb;
    DTimer timer;
    bool sended = false;

    TMsgContext(boost::asio::any_io_executor  ex);
};

typedef std::shared_ptr<TMsgContext> TMsgContextPtr;

class TunnelSession;
typedef std::shared_ptr<TunnelSession> TunnelSessionPtr;

class TunnelSession : public std::enable_shared_from_this<TunnelSession>
{
public:
    TunnelSession(const string& session_id);
    virtual ~TunnelSession();

    virtual void async_run(RunCallback&& cb) = 0;
    virtual void cancel() = 0;

    virtual void async_request(StringRequest req, int timeout, RequestCallback&& cb) = 0;

protected:
    //void loop_send(BSErrorCode ec);

    //void loop_recv(BSErrorCode ec);

    TMsgContextPtr get_non_send_tmsg();

    void callback_by_timeout(const string& tid);

    void callback_by_error(const string& tid, BSErrorCode ec);

    void callback_by_recv_response(const string& tid, StringResponse res);

protected:
    //TcpSocket m_socket;
    Endpoint m_remote_ep;
    string m_session_id;

    vector<TMsgContextPtr> m_all_req_cxt;
    uint32_t m_tid = 1;

    RunCallback m_cb;

    Coroutine m_send_co;
    Coroutine m_recv_co;

    //DTimer m_wait_send_timer;
    TMsgContextPtr m_cur_send_msg_cxt;

    boost::beast::flat_buffer m_recv_buffer;
    StringResponse m_recv_res;

    std::mutex m_mutex;
};

#endif // TUNNEL_SESSION_H
