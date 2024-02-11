#include "../include/network.hpp"

/*Network::PHeader Network::ParseHeader(Network::Client *client) {
  PHeader header = new Header;
  ssize_t buffer_size = client->get_buffer_size();
  char* copy_buffer = (char*)calloc(NETWORK_HEADER_SIZE, 1);
  if (copy_buffer == NULL) {
    delete header;
    return nullptr;
  }

  if (buffer_size < NETWORK_HEADER_SIZE) {
    header->packet_size = 0;
    header->packet_type = Network::PACKET_TYPE::INVALID;
    return header;
  }

  memcpy(copy_buffer, client->get_buffer_ptr(), NETWORK_HEADER_SIZE);
  uint16_t magic = *(uint16_t*)copy_buffer;

  if (magic != NETWORK_HEADER_MAGIC) {
    header->packet_size = 0;
    header->packet_type = Network::PACKET_TYPE::INVALID;
    return header;
  }

  uint8_t packet_type = copy_buffer[NETWORK_HEADER_TYPE_ADDR];
  header->packet_type = (Network::PACKET_TYPE)packet_type;
  uint64_t packet_size = *(size_t*)(copy_buffer + NETWORK_HEADER_DATA_SIZE_ADDR);
  header->packet_size = packet_size;
  free(copy_buffer);
  return header;
}*/


Network::PHeader Network::ParseHeader(char _buffer[NETWORK_HEADER_SIZE]) {
  using namespace Network;
  PHeader header = new Header;
  header->packet_size = 0;
  uint16_t magic = *((uint16_t*)_buffer);
  if (magic != NETWORK_HEADER_MAGIC) {
    header->packet_type = PACKET_TYPE::INVALID;
    return header;
  }
  header->packet_type = (PACKET_TYPE)(_buffer[NETWORK_HEADER_TYPE_ADDR]);
  header->packet_size = *((uint64_t*)&_buffer[NETWORK_HEADER_DATA_SIZE_ADDR]);
  return header;
}

Network::PMessage Network::ParseMessage(Network::Client* client, Network::PHeader header) {
  using namespace Network;
  if (header->packet_type != PACKET_TYPE::MESSAGE) return nullptr;
  PMessage message = new Message;
  message->emmitter_id = client->unique_id;
  message->emmitter_name = client->get_name();
  message->message_content = "";
  if (header->packet_size < 1) return message;
  char* message_data = (char*)calloc(header->packet_size, 1);
  if (message_data == NULL) {
    delete message;
    return nullptr;
  }
  message->message_content = message_data;
  free(message_data);
  return message;
}


Network::Server::Server() {
  using namespace Network;
  this->_awaiting_messages = std::vector<PMessage>();
  this->_running = false;
  this->_port = 0;
  this->_socket = 0;
  this->_opened_client_connections = std::vector<Client*>();
}

bool Network::Server::start(unsigned short port) {
  this->_socket = socket(AF_INET, SOCK_STREAM, NULL);
  if (this->_socket < 0) return false;
  sockaddr_in addr = { 0 };
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(port);
  addr.sin_family = AF_INET;
  if (bind(this->_socket, (sockaddr*)&addr, sizeof(addr)) < 0) return false;
  if (listen(this->_socket, 5) < 0) return false;
  this->_running = true;
  this->_accept_thread = std::thread(&Server::accept_loop, this);
  return true;
}

bool Network::Server::stop(void) {
  if (!this->_running) return false;
  this->_running = false;
  for (auto i : this->_opened_client_connections) {
    shutdown(i->get_socket(), SHUT_RDWR);
    close(i->get_socket());
    delete i;
  }
  this->_opened_client_connections.clear();
  this->_awaiting_messages.clear();
  this->_port = 0;
  if (this->_accept_thread.joinable())
    this->_accept_thread.join();
  return true;
}

void Network::Server::accept_loop(void) {
  using namespace Network;
  while (this->_running) {
    int new_conn = accept(this->_socket, NULL, NULL);
    Client* client = new Client(new_conn, &this->_awaiting_messages, this->_opened_client_connections.size(), this);
    this->_opened_client_connections.push_back(client);
  }
}

Network::Client::Client(int _fd, std::vector<Network::PMessage>* _associated_messages, int unique_id, Server* server) {
  this->_socket = _fd;
  this->_associated_messages_vector = _associated_messages;
  this->_authenticated = false;
  this->_name = "";
  this->_buffer_size = 0;
  this->unique_id = unique_id;
  this->run_recieve = true;
  this->_recv_thread = std::thread(&Client::recv_loop, this);
  this->_associated_server = server;
}

void Network::Client::recv_loop(void) {
  using namespace Network;
  while (this->run_recieve) {
    char _buffer[NETWORK_HEADER_SIZE] = { 0 };
    if (recv(this->_socket, _buffer, NETWORK_HEADER_SIZE, NULL) < 0) {
      this->run_recieve = false;
      this->_authenticated = false;
      this->~Client();
      return;
    }
    PHeader header = ParseHeader(_buffer);
    if (header->packet_type == INVALID) {
      SendError(this->_socket, ERROR_TYPE::INVALID_PACKET);
      shutdown(this->_socket, SHUT_RDWR);
      close(this->_socket);
      this->run_recieve = false;
      this->~Client();
      return;
    }
    switch (header->packet_type)
    {
    case PACKET_TYPE::MESSAGE:
      this->_handleMessage(header);
      break;
    case PACKET_TYPE::AUTH:
      this->_handleUsername(header);
      break;
    case PACKET_TYPE::DEAUTH:
      this->_handleDeauth(header);
      break;
    default:
      break;
    }
  }
}

char* Network::SerializeHeader(PHeader _header) {
  using namespace Network;
  
  // Allocation buffer
  char* buffer = (char*)calloc(NETWORK_HEADER_SIZE, 1);
  if (buffer == NULL) return nullptr;                     //Echec d'allocation => retourne nullptr
  ((uint16_t*)(buffer))[0] = NETWORK_HEADER_MAGIC;        // Ajout du mot magique
  buffer[2] = _header->packet_type;                       // Ajout du type de paquet
  *((uint64_t*)(&buffer[NETWORK_HEADER_DATA_SIZE_ADDR])) = _header->packet_size; // Ajout de la taille de paquet
  return buffer;
}

void Network::SendError(int _fd, Network::ERROR_TYPE error) {
  using namespace Network;
  PHeader header = new Header;
  header->packet_type = PACKET_TYPE::ERROR;
  header->packet_size = sizeof(ERROR_TYPE);
  char* serialized_header = SerializeHeader(header);
  if (serialized_header == nullptr) return;
  char* buffer = (char*)calloc(NETWORK_HEADER_SIZE + sizeof(ERROR_TYPE), 1);
  if (buffer == NULL) return;
  memcpy(buffer, serialized_header, NETWORK_HEADER_SIZE);
  *((ERROR_TYPE*)(&buffer[NETWORK_HEADER_SIZE])) = error;
  send(_fd, buffer, NETWORK_HEADER_SIZE + sizeof(ERROR_TYPE), NULL);
  free(buffer);
  free(serialized_header);
  delete header;
}

void Network::Client::_sendConfirmation(void) {
  using namespace Network;
  PHeader header = new Header;
  header->packet_size = 0;
  header->packet_type = PACKET_TYPE::CONFIRMATION;
  char* serialized_header = SerializeHeader(header);
  if (serialized_header == NULL) {
    delete header;
    return;
  }
  send(this->_socket, serialized_header, NETWORK_HEADER_SIZE, NULL);
}

void Network::Client::_handleMessage(PHeader header) {
  char* message_buffer = (char*)calloc(header->packet_size + 1, 1);
  if (message_buffer == NULL) {
    SendError(this->_socket, ERROR_TYPE::INTERNAL_SERVER_ERROR);
    return;
  }
  read(this->_socket, message_buffer, header->packet_size);
  std::string message_str = message_buffer;
  free(message_buffer);
  PMessage message = new Message;
  message->emmitter_id = this->unique_id;
  message->emmitter_name = this->_name;
  message->message_content = message_str;
  this->_associated_messages_vector->push_back(message);
}

void Network::Client::_handleUsername(PHeader header) {
  uint64_t name_length = header->packet_size;
  char* buffer = (char*)calloc(name_length + 1, 1);
  read(this->_socket, buffer, name_length);
  std::string username = buffer;
  
}
