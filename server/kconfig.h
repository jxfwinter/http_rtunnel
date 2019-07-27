#ifndef KCONFIG_H
#define KCONFIG_H

#include <memory>
#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <thread>
#include <boost/beast.hpp>
#include <boost/asio.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/date_time.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/crc.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/date_time/gregorian/gregorian.hpp>
#include <boost/date_time/gregorian/greg_duration.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>
#include <boost/unordered_map.hpp>
#include <boost/thread.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>

#include "logger.h"

using namespace std;
using namespace boost;
using namespace boost::posix_time;
using namespace boost::uuids;
using namespace boost::property_tree;


typedef boost::asio::io_context IoContext;
typedef boost::asio::ip::tcp::acceptor Acceptor;
typedef boost::asio::ip::tcp::endpoint Endpoint;
typedef boost::asio::ip::tcp::socket TcpSocket;
typedef boost::asio::coroutine Coroutine;
typedef boost::asio::ip::tcp::resolver Resolver;
typedef boost::asio::ip::tcp::resolver::results_type ResolverResult;
typedef boost::asio::deadline_timer DTimer;
using namespace boost::asio::ip;

typedef boost::system::error_code BSErrorCode;
namespace http = boost::beast::http;
typedef http::request<http::string_body> StringRequest;
typedef http::response<http::string_body> StringResponse;

#define SESSION_ID "JR-SID"
#define TID "TID-J"

struct ConfigParams
{
    string http_listen_addr = "0.0.0.0";
    uint16_t http_listen_port = 3080;

    string https_listen_addr = "0.0.0.0";
    uint16_t https_listen_port = 3443;

    string ssl_certificate;
    string ssl_certificate_key;

    uint16_t thread_pool = 3;

    string tunnel_listen_addr = "0.0.0.0";
    uint16_t tunnel_listen_port = 3081;
    uint16_t tunnel_thread_pool = 3;

    uint16_t req_timeout_secs = 15;

    string log_path = "./http_rrproxy.log";
    boost::log::trivial::severity_level log_level = boost::log::trivial::debug;
};

//初始化参数
bool init_params(int argc, char** argv, ConfigParams& params);

extern ConfigParams* g_cfg;

#endif
