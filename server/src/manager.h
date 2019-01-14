#ifndef MANAGER_H
#define MANAGER_H

#include "kconfig.h"

class WSHttpSession;

typedef std::shared_ptr<WSHttpSession> WSHttpSessionPtr;

class Manager
{
public:
    Manager();
    ~Manager();

    void start();

    void stop();

    //返回true成功, 返回false失败
    bool add_session(const string& url, const string& token, WSHttpSessionPtr session);
    //返回nullptr表示没找到
    WSHttpSessionPtr find_session(const string& url, const string& token);
    void remove_session(const string& url, const string& token, WSHttpSessionPtr session);

private:
    void process_http_req(RequestContext& cxt);

    string req_to_buffer(StrRequest& req);
    StrResponse buffer_to_res(const string& parser_buf);

private:
    RequestApiServer m_http_server;
    WsServer m_ws_server;
    //key为url，不带?后面的参数
    std::map<string,  std::unordered_map<string, WSHttpSessionPtr>> m_url_token_session;

    int m_ws_session_count = 0;
    boost::fibers::mutex m_mutex;
};


#endif // MANAGER_H
