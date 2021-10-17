#ifndef SERVER_SOCKS5_HPP
#define SERVER_SOCKS5_HPP

#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/endian/conversion.hpp>
#include <boost/system/error_code.hpp>
#include <chrono>
#include <iostream>
#include <memory>
#include <sstream>


namespace SOCKS5 {

namespace ba = boost::asio;
using boost::beast::tcp_stream;
using boost::endian::big_to_native;
using boost::system::error_code;
using tcp = ba::ip::tcp;

void listen(ba::io_context& ctx, tcp::endpoint endpoint, ba::yield_context yield);

template<typename T>
void print_bytes(std::size_t bytes, const T& buffer, const std::string& action) {
    std::stringstream ss;
    ss << action << ": ";
    for (std::size_t i = 0; i < bytes; ++i) {
        ss << std::hex << std::internal << std::setfill('0')
           << std::setw(2) << (0xFF & static_cast<int>(buffer[i])) << ' ';
    }
    std::cout << ss.str() << '\n';
}

bool check_error_code(error_code ec, const std::string& ec_text);

class Session : public std::enable_shared_from_this<Session> {
public:
    Session(
        tcp::socket client_socket,
        std::size_t buffer_size = (1 << 14),
        std::size_t timeout = 60
    );
    void launch();

private:
    bool handshake(const ba::yield_context& yield, const std::shared_ptr<Session>& self);
    void echo(tcp_stream& source, tcp_stream& destination, const ba::yield_context& yield);
    bool is_client_connection_request_valid();
    std::string endpoint_to_string() const;

    std::chrono::seconds timeout;
    std::size_t buffer_size;
    std::vector<std::uint8_t> client_buffer;
    std::uint8_t client_connection_request[10] =
        {0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    std::uint8_t server_choice[2] = {0x05, 0xFF};
    std::string printed_address;
    tcp::endpoint endpoint;
    tcp::resolver resolver;
    tcp_stream client_stream;
    tcp_stream remote_stream;
};

}

#endif
