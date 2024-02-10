#pragma once
#include "commons.hpp"

#define NETWORK_HEADER_SIZE 3
#define NETWORK_HEADER_MAGIC 0xBABE
#define NETWORK_HEADER_MAGIC_SIZE 2
#define NETWORK_HEADER_MAGIC_ADDR 0
#define NETWORK_HEADER_TYPE_SIZE 1
#define NETWORK_HEADER_TYPE_ADDR 1

namespace Network {

    typedef enum PACKET_TYPE {
        AUTH,
        DEAUTH,
        MESSAGE,
        ERROR,
        INVALID,
    };

    typedef enum ERROR_TYPE {
        INVALID_USERNAME,
        INTERNAL_SERVER_ERROR,
        FORBIDDEN,
        INVALID_PACKET,
    };

    typedef struct {
        int emmitter_id;
        std::string emmitter_name;
        std::string message_content;
    } Message, *PMessage;

    typedef struct {
        PACKET_TYPE packet_type;
        ssize_t packet_size;
    } Header, *PHeader;

    class Client {
        public:
        Client();
        ~Client();

        void recv_loop(void);

        int unique_id;

        private:

        int _socket;
        ssize_t _buffer_size;
        char* _buffer;
        std::string _name;
        bool _authenticated;
        sockaddr_in _address;

    };


    // Retourne un pointeur vers une structure Message. Permet l'extraction des données
    // d'un message depuis un client
    PMessage ParseMessage(Client* client);


    // Retourne un pointeur vers une structure Header. Permet la reconnaissance du type d'un paquet.
    // Si le paquet reçu est invalide, le membre packet_type de la structure Header vaudra PACKET_TYPE::INVALID
    // @warning Pensez à désallouer la mémoire avec delete car le Header est créé avec new
    PHeader ParseHeader(Client* client);

    class Server {
        public:
        Server();
        ~Server();

        void stop(void) { this->_running = false; }

        void accept_loop(bool*);
        void treat_message_loop(bool*);
        std::vector<PMessage>* get_treated_messages(void);
        private:

        std::thread _accept_thread;
        std::thread _treat_message_thread;

        std::vector<PMessage> _awaiting_messages;
        std::vector<PMessage> _treated_messages;

        std::vector<Client*> _opened_client_connections;

        bool _running;

        int _port;
        int _socket;

    };
}