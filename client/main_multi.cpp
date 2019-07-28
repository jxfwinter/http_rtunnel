#include "http_tunnel_client.h"
#include <iostream>
#include <vector>
#include <thread>
using namespace std;
#include <boost/lexical_cast.hpp>

int main(int argc,char ** argv)
{
    if(argc != 6)
    {
        std::cerr <<
                     "Usage: " << argv[0] << " <host> <port> <session_id> <local_port> <count>\n" <<
                     "Example:\n    " << argv[0] <<
                     " 121.199.4.198 28080 test1122 3080 100\n";
        return EXIT_FAILURE;
    }

    string host = argv[1];
    int port = boost::lexical_cast<int>(string(argv[2]));
    string session_id = argv[3];
    int local_port = boost::lexical_cast<int>(string(argv[4]));
    int count = boost::lexical_cast<int>(string(argv[5]));

    int thread_pool = 3;
    IoContext ioc{thread_pool};

    for(int i=1; i<=count; ++i)
    {
        string session_id_tmp = session_id + boost::lexical_cast<string>(i);
        HttpTunnelClient* ht = new HttpTunnelClient(ioc);
        ht->set_transmit_local_address("127.0.0.1", local_port);
        ht->set_conn_cb([session_id_tmp](SOCKET_STATUS s){
            cout << session_id_tmp << ":" << (int)s << endl;
        });

        ht->start(host, port, session_id_tmp);
    }

    std::vector<std::thread> v;
    v.reserve(thread_pool - 1);
    for(auto i = thread_pool - 1; i > 0; --i)
    {
        v.emplace_back([&ioc]{
            ioc.run();
        });
    }

    ioc.run();
    return 0;
}