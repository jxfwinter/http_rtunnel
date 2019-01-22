#include "http_tunnel.h"
#include "manager.h"

HttpTunnel::HttpTunnel(TcpSocket &s, Manager& svr) :
    m_socket(std::move(s)), m_svr(svr)
{

}

HttpTunnel::~HttpTunnel()
{

}

void HttpTunnel::start()
{

}

void HttpTunnel::stop()
{

}

StrResponse HttpTunnel::request(StrRequest& req)
{

}

bool HttpTunnel::is_allow(const WsSessionContext& cxt)
{
    auto it = cxt.query_params.find("token");
    if(it == cxt.query_params.end())
    {
        return false;
    }

    const string& token = it->second;
    return m_svr.add_session(cxt.path, token, std::static_pointer_cast<HttpTunnel>(shared_from_this()));
}

void HttpTunnel::on_close(const WsSessionContext& cxt)
{
    auto it = cxt.query_params.find("token");
    if(it == cxt.query_params.end())
    {
        return;
    }
    const string& token = it->second;
    m_svr.remove_session(cxt.path, token, std::static_pointer_cast<HttpTunnel>(shared_from_this()));
    LogDebug << "on close,url:" << cxt.path << ",token:" << token;
}

void HttpTunnel::on_error(const WsSessionContext& cxt)
{
    auto it = cxt.query_params.find("token");
    if(it == cxt.query_params.end())
    {
        return;
    }
    const string& token = it->second;
    m_svr.remove_session(cxt.path, token, std::static_pointer_cast<HttpTunnel>(shared_from_this()));
    LogError << "on error,url:" << cxt.path << ",token:" << token;
}
