#include "util.hpp"


namespace SOCKS5 {

void listen(ba::io_context& ctx, tcp::endpoint endpoint, ba::yield_context yield) {
    error_code ec;
    tcp::acceptor acceptor(ctx);

    acceptor.open(endpoint.protocol(), ec);
    if (ec)
        throw std::runtime_error("acceptor.open(): " + ec.message());

    acceptor.set_option(ba::socket_base::reuse_address(true), ec);
    if (ec)
        throw std::runtime_error("acceptor.set_option(reuse_address): " + ec.message());

    acceptor.bind(endpoint, ec);
    if (ec)
        throw std::runtime_error("acceptor.bind(): " + ec.message());

    acceptor.listen(ba::socket_base::max_listen_connections, ec);
    if (ec)
        throw std::runtime_error("acceptor.listen(): " + ec.message());

    for (;;) {
        tcp::socket socket(ba::make_strand(acceptor.get_executor()));
        acceptor.async_accept(socket, yield[ec]);
        if (ec)
            throw std::runtime_error("acceptor.async_accept(socket): " + ec.message());
        else {
            std::cout << "Socket accepted\n";
            if (!ec)
                std::make_shared<SOCKS5::Session>(std::move(socket))->launch();
        }
    }
}

bool check_error_code(error_code ec, const std::string& ec_text = "Error: ") {
    if (!ec)
        return true;
    std::cerr << ec_text << ec.message() << '\n';
    return false;
}

Session::Session(tcp::socket client_socket, std::size_t buffer_size, std::size_t timeout)
    : timeout(timeout),
      buffer_size(buffer_size),
      client_buffer(buffer_size),
      resolver(client_socket.get_executor()),
      client_stream(std::move(client_socket)),
      remote_stream(ba::make_strand(client_socket.get_executor())) {}

bool Session::handshake(const ba::yield_context& yield, const std::shared_ptr<Session>& self) {
    error_code ec;

    tcp::endpoint endpoint = client_stream.socket().remote_endpoint(ec);
    std::string socket;
    if (ec)
        socket = "Closed socket";
    else
        socket = endpoint.address().to_string()
                 + ":"
                 + std::to_string(big_to_native(endpoint.port()));

    std::cout << "Local address: " << socket << '\n';

    // Client greeting (VER, NAUTH, AUTH)

    self->client_stream.expires_after(self->timeout);
    std::size_t read_bytes = ba::async_read(
        self->client_stream,
        ba::buffer(self->client_buffer, 2),
        yield[ec]
    );
    if (!check_error_code(ec, "Error in client greeting (VER and NAUTH): "))
        return false;

    print_bytes<std::vector<std::uint8_t>>(
        read_bytes,
        self->client_buffer,
        "Read VER and NAUTH"
    );

    if (self->client_buffer[0] != 0x05) {
        std::cerr << "Error in client greeting (VER != 5): "
                  << unsigned(self->client_buffer[0])
                  << '\n';
        return false;
    }

    std::uint8_t nauth = self->client_buffer[1];
    self->client_stream.expires_after(self->timeout);
    read_bytes = ba::async_read(
        self->client_stream,
        ba::buffer(self->client_buffer, nauth),
        yield[ec]
    );
    if (!check_error_code(ec, "Error in client greeting (AUTH): "))
        return false;

    print_bytes<std::vector<std::uint8_t>>(read_bytes, self->client_buffer, "Read AUTH");

    // Server choice (VER, CAUTH)

    for (std::uint8_t auth_method = 0; auth_method < nauth; ++auth_method)
        if (self->client_buffer[auth_method] == 0x00) {
            self->server_choice[1] = 0x00;
            break;
        }

    self->client_stream.expires_after(self->timeout);
    std::size_t written_bytes = async_write(
        self->client_stream,
        ba::buffer(self->server_choice, 2),
        yield[ec]
    );

    if (!check_error_code(ec, "Error in server response (VER, CAUTH): "))
        return false;

    print_bytes(written_bytes, server_choice, "Wrote VER and CAUTH");

    if (self->client_buffer[1] == 0xFF) {
        std::cout << "Unsupported authentification method (CAUTH = 0xFF): "
                  << unsigned(self->client_buffer[1])
                  << '\n';
        return false;
    }

    // Client connection request (VER, CMD, RSV, TYPE, DSTADDR, DSTPORT)

    self->client_stream.expires_after(self->timeout);
    read_bytes = ba::async_read(
        self->client_stream,
        ba::buffer(self->client_buffer, 4),
        yield[ec]
    );
    if (!check_error_code(ec, "Error in client connection request (VER, CMD, RSV, TYPE): "))
        return false;

    print_bytes(read_bytes, self->client_buffer, "Read VER, CMD, RSV, TYPE");

    if (self->is_client_connection_request_valid()) {
        if (self->client_buffer[3] == 0x03) { // TYPE = domain name
            self->client_stream.expires_after(self->timeout);
            ba::async_read(self->client_stream, ba::buffer(self->client_buffer, 1), yield[ec]);
            if (!check_error_code(ec, "Error in reading domain name length: "))
                return false;

            std::uint8_t name_length = self->client_buffer[0];
            self->client_stream.expires_after(self->timeout);
            ba::async_read(
                self->client_stream,
                ba::buffer(self->client_buffer, name_length + 2),
                yield[ec]
            );
            if (!check_error_code(ec, "Error in reading domain name: "))
                return false;

            self->printed_address = std::string(
                self->client_buffer.begin(),
                self->client_buffer.begin() + name_length
            );

            std::uint16_t port;
            std::memcpy(&port, client_buffer.data() + name_length, 2);
            std::string str_port = std::to_string(big_to_native(port));

            self->printed_address += ':' + str_port;

            std::cout << "Read domain name: " << self->printed_address << '\n';

            std::string remote_host(reinterpret_cast<char*>(client_buffer.data()), name_length);
            tcp::resolver::query query(remote_host, std::to_string(big_to_native(port)));
            tcp::resolver::iterator endpoint_iterator = resolver.async_resolve(query, yield[ec]);
            if (ec) {
                std::cerr << "Error in domain name resolution\n";
                client_connection_request[1] = 0x03;
                return false;
            }
            endpoint = *endpoint_iterator;
        } else { // TYPE = IPv4
            self->client_stream.expires_after(self->timeout);
            ba::async_read(self->client_stream, ba::buffer(self->client_buffer, 6), yield[ec]);

            if (!check_error_code(ec, "Error in reading IPv4 address and port: "))
                return false;

            self->endpoint = tcp::endpoint(
                ba::ip::address_v4(big_to_native(*((uint32_t *) &self->client_buffer[0]))),
                big_to_native(*((uint16_t *) &self->client_buffer[4]))
            );

            self->printed_address = self->endpoint_to_string();

            std::cout << "Read endpoint: " << self->printed_address << '\n';
        }
    }

    // Connection to remote server

    if (self->client_connection_request[1] == 0x00) {
        self->remote_stream.expires_after(self->timeout);
        self->remote_stream.async_connect(self->endpoint, yield[ec]);

        if (!check_error_code(ec, "Error in connection to remote server: ")) {
            self->client_connection_request[1] = 0x03;
            std::cout << "Cannot connect to " << self->endpoint_to_string() << '\n';
        } else {
            auto remote_endpoint = self->remote_stream.socket().local_endpoint();
            auto client_endpoint = self->client_stream.socket().local_endpoint();

            uint32_t real_local_ip = big_to_native(remote_endpoint.address().to_v4().to_uint());
            uint16_t real_local_port = big_to_native(remote_endpoint.port());
            std::memcpy(&self->client_connection_request[4], &real_local_ip, 4);
            std::memcpy(&self->client_connection_request[8], &real_local_port, 2);

            std::cout << "Connected: "
                      << client_endpoint.address().to_string()
                      << ':'
                      << std::to_string(big_to_native(client_endpoint.port()))
                      << " to "
                      << self->printed_address
                      << '\n';
        }
    }

    self->client_stream.expires_after(self->timeout);
    async_write(self->client_stream, ba::buffer(self->client_connection_request, 10), yield[ec]);

    if (!check_error_code(ec, "Error in writing client connection request: "))
        return false;

    return true;
}

void Session::launch() {
    auto self(shared_from_this());
    ba::spawn(client_stream.get_executor(), [self](const ba::yield_context &yield) {
        if (!self->handshake(yield, self)) {
            std::cerr << "Handshake failed\n";
            return;
        }
        ba::spawn(self->client_stream.get_executor(), [self](const ba::yield_context &yield) {
            self->echo(self->client_stream, self->remote_stream, yield);
        });
        self->echo(self->remote_stream, self->client_stream, yield);
    });
}

void Session::echo(
    tcp_stream &source,
    tcp_stream &destination,
    const ba::yield_context &yield
) {
    error_code ec;
    std::vector<std::uint8_t> buffer(buffer_size);
    for (;;) {
        std::size_t n = source.async_read_some(ba::buffer(buffer), yield[ec]);
        if (ec) return;

        destination.async_write_some(ba::buffer(buffer, n), yield[ec]);
        if (ec) return;
    }
}

bool Session::is_client_connection_request_valid() {
    // VER - SOCKS version (0x05 for SOCKS5)
    if (client_buffer[0] != 0x05) {
        std::cout << "Client connection request invalid - VER != 0x05: "
                  << unsigned(client_buffer[0])
                  << '\n';
        client_connection_request[1] = 0xFF;
        return false;
    }
    // CMD - command code:
    //   0x01: establish a TCP/IP stream connection
    //   0x02: establish a TCP/IP port binding
    //   0x03: associate a UDP port
    if (client_buffer[1] != 0x01) {
        std::cout << "Client connection request invalid - CMD not supported: "
                  << unsigned(client_buffer[1])
                  << '\n';
        client_connection_request[1] = 0x07;
        return false;
    }
    // RSV - reserved (must be 0x00)
    if (client_buffer[2] != 0x00) {
        std::cout << "Client connection request invalid - RSV != 0x00\n";
        client_connection_request[1] = 0x01;
        return false;
    }
    // TYPE - address type:
    //   0x01: IPv4
    //   0x03: domain name
    if (client_buffer[3] != 0x01 && client_buffer[3] != 0x03) {
        std::cout << "Client connection request invalid - TYPE not supported: "
                  << unsigned(client_buffer[3])
                  << '\n';
        client_connection_request[1] = 0x08;
        return false;
    }
    return true;
}

std::string Session::endpoint_to_string() const {
    return endpoint.address().to_string() + ":" + std::to_string(endpoint.port());
}

}
