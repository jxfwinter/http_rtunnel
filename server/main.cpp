#include "kconfig.h"
#include "http_tunnel_server.h"
#include <iostream>

int main(int argc,char ** argv)
{
    g_cfg = new ConfigParams();
    //初始化
    if(!init_params(argc, argv, *g_cfg))
    {
        return 1;
    }

    init_logging(g_cfg->log_path, g_cfg->log_level, true);
    LogDebug << "start server";
    IoContext ioc;

    HttpTunnelServer server(ioc, g_cfg->http_listen_addr, g_cfg->http_listen_port);
    server.start();

    std::vector<std::thread> v;
    v.reserve(g_cfg->thread_pool - 1);
    for(auto i = g_cfg->thread_pool - 1; i > 0; --i)
    {
        v.emplace_back([&ioc]{
            ioc.run();
        });
    }
    ioc.run();
    return 0;
}
