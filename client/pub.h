#ifndef PUB_H
#define PUB_H

#include <boost/asio/ip/tcp.hpp>
typedef boost::asio::ip::tcp::socket TcpSocket;

void set_socket_opt(TcpSocket& socket);

#endif
