#include "http_tunnel.h"
#include <iostream>
using namespace std;
#include <boost/lexical_cast.hpp>

int main(int argc,char ** argv)
{
    if(argc != 5)
    {
        std::cerr <<
                     "Usage: " << argv[0] << " <host> <port> <session_id> <local_port>\n" <<
                     "Example:\n    " << argv[0] <<
                     " 121.199.4.198 28080 test1122 3080 \n";
        return EXIT_FAILURE;
    }

    string host = argv[1];
    int port = boost::lexical_cast<int>(string(argv[2]));
    string session_id = argv[3];
    int local_port = boost::lexical_cast<int>(string(argv[4]));

    IoContext ioc;
    HttpTunnel ht(ioc);
    ht.set_transmit_local_address("127.0.0.1", local_port);
    ht.set_conn_cb([](SOCKET_STATUS s){
        cout << (int)s << endl;
    });

    ht.start(host, port, session_id);

    ioc.run();
    return 0;
}
