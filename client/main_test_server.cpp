#include "http_api_server.h"
#include <boost/lexical_cast.hpp>

int main(int argc,char ** argv)
{
    if(argc != 2)
    {
        std::cerr <<
                     "Usage: " << argv[0] << " <listen_port> \n" <<
                     "Example:\n    " << argv[0] <<
                     " 30080\n";
        return EXIT_FAILURE;
    }

    int listen_port = boost::lexical_cast<int>(string(argv[1]));
    IoContext ioc;
    HttpApiServer http_server(ioc, "0.0.0.0", listen_port);
    http_server.start();
    ioc.run();
    return 0;
}
