#ifndef HTTP_TUNNEL_SESSION_H
#define HTTP_TUNNEL_SESSION_H

#include "kconfig.h"
class HttpTunnelServer;

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

    TMsgContext(boost::asio::executor ex);
};

typedef std::shared_ptr<TMsgContext> TMsgContextPtr;

class HttpTunnelSession;
typedef std::shared_ptr<HttpTunnelSession> HttpTunnelSessionPtr;

class HttpTunnelSession : public std::enable_shared_from_this<HttpTunnelSession>
{
public:
    HttpTunnelSession(TcpSocket &s, const string& session_id);
    ~HttpTunnelSession();

    void async_run(RunCallback&& cb);

    void async_request(StringRequest req, int timeout, RequestCallback&& cb);

private:
    void loop_send(BSErrorCode ec);

    void loop_recv(BSErrorCode ec);

    TMsgContextPtr get_non_send_tmsg();

    void callback_by_timeout(const string& tid);

    void callback_by_error(const string& tid, BSErrorCode ec);

    void callback_by_recv_response(const string& tid, StringResponse res);

private:
    TcpSocket m_socket;
    string m_session_id;

    vector<TMsgContextPtr> m_all_req_cxt;
    uint32_t m_tid = 1;

    RunCallback m_cb;

    Coroutine m_send_co;
    Coroutine m_recv_co;

    DTimer m_wait_send_timer;
    string m_cur_send_tid;

    boost::beast::flat_buffer m_recv_buffer;
    StringResponse m_recv_res;

    std::mutex m_mutex;
};

#endif // HTTP_TUNNEL_SESSION_H
