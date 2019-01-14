#include "ws_http_session.h"
#include "manager.h"

WSHttpSession::WSHttpSession(WsSessionContext& cxt, tcp::socket &s, Manager& svr) :
    WsCallSession(cxt, s), m_svr(svr)
{

}

WSHttpSession::~WSHttpSession()
{

}

bool WSHttpSession::is_allow(const WsSessionContext& cxt)
{
    auto it = cxt.query_params.find("token");
    if(it == cxt.query_params.end())
    {
        return false;
    }

    const string& token = it->second;
    return m_svr.add_session(cxt.path, token, std::static_pointer_cast<WSHttpSession>(shared_from_this()));
}

void WSHttpSession::on_close(const WsSessionContext& cxt)
{
    auto it = cxt.query_params.find("token");
    if(it == cxt.query_params.end())
    {
        return;
    }
    const string& token = it->second;
    m_svr.remove_session(cxt.path, token, std::static_pointer_cast<WSHttpSession>(shared_from_this()));
    LogDebug << "on close,url:" << cxt.path << ",token:" << token;
}

void WSHttpSession::on_error(const WsSessionContext& cxt)
{
    auto it = cxt.query_params.find("token");
    if(it == cxt.query_params.end())
    {
        return;
    }
    const string& token = it->second;
    m_svr.remove_session(cxt.path, token, std::static_pointer_cast<WSHttpSession>(shared_from_this()));
    LogError << "on error,url:" << cxt.path << ",token:" << token;
}
