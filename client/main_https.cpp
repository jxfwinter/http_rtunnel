#include "https_tunnel_client.h"
#include <iostream>
#include <vector>
#include <thread>
using namespace std;
#include <boost/lexical_cast.hpp>

#define KK_PRT(fmt...)   \
    do {\
    time_t timep;\
    time(&timep);\
    tm* tt = localtime(&timep); \
    printf("[%d-%02d-%02d %02d:%02d:%02d][%s]-%d: ", tt->tm_year+1900,tt->tm_mon+1,tt->tm_mday,tt->tm_hour,tt->tm_min,tt->tm_sec, __FUNCTION__, __LINE__);\
    printf(fmt);\
    printf("\n");\
    }while(0)

typedef std::shared_ptr<IoContext> IoContextPtr;
int main(int argc,char ** argv)
{
    if(argc != 6 && argc != 7)
    {
        std::cerr <<
                     "Usage: " << argv[0] << " <host> <port> <session_id> <local_port> <count> <verify_file so csr>\n" <<
                     "Example:\n    " << argv[0] <<
                     " 121.199.4.198 28080 test1122 3080 100 ../config/CARoot1024.crt\n";
        return EXIT_FAILURE;
    }

    string host = argv[1];
    int port = boost::lexical_cast<int>(string(argv[2]));
    string session_id = argv[3];
    int local_port = boost::lexical_cast<int>(string(argv[4]));
    int count = boost::lexical_cast<int>(string(argv[5]));
    string verify_file;
    if(argc == 7)
    {
        verify_file = argv[6];
    }

    int thread_pool = 3;
    std::vector<IoContextPtr> ioc_pool;
    for(int i = 0; i < thread_pool; ++i)
    {
        IoContextPtr ioc_ptr(new IoContext());
        ioc_pool.push_back(ioc_ptr);
    }

    SslContext ssl_cxt(boost::asio::ssl::context::sslv23);
    if(!verify_file.empty())
    {
        ssl_cxt.load_verify_file(verify_file);
    }

    for(int i=1; i<=count; ++i)
    {
        string session_id_tmp = session_id + boost::lexical_cast<string>(i);

        HttpsTunnelClientPtr ht(new HttpsTunnelClient(*ioc_pool[i%thread_pool], ssl_cxt, !verify_file.empty()));
        ht->async_run(host, port, session_id_tmp, "127.0.0.1", local_port, [session_id_tmp](SOCKET_STATUS s){
            cout << session_id_tmp << ":" << (int)s << endl;
        });
    }

    typedef boost::asio::executor_work_guard<boost::asio::io_context::executor_type> io_context_work;
    std::vector<std::thread> v;
    v.reserve(thread_pool);
    for(int i = 0; i < thread_pool; ++i)
    {
        auto& ioc = *ioc_pool[i];
        v.push_back(std::thread([&ioc] {
            io_context_work ioc_worker = boost::asio::make_work_guard(ioc);
            ioc.run();
            ioc_worker.reset();
        }));
    }

    for(auto& t : v)
    {
        t.join();
    }
    return 0;
}
