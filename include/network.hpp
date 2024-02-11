#pragma once
#include "commons.hpp"

#define NETWORK_HEADER_SIZE 11
#define NETWORK_HEADER_MAGIC 0xBABE
#define NETWORK_HEADER_MAGIC_SIZE 2
#define NETWORK_HEADER_MAGIC_ADDR 0
#define NETWORK_HEADER_TYPE_SIZE 1
#define NETWORK_HEADER_TYPE_ADDR 2
#define NETWORK_HEADER_DATA_SIZE_SIZE 8
#define NETWORK_HEADER_DATA_SIZE_ADDR 3

// Structure d'un paquet (Tailles données en octets et addresse données en octets)
// DESCRIPTION (VALEUR)[ADDRESSE]{TAILLE}
// MOT MAGIQUE (0xBABE)[0]{2}
// TYPE PAQUET (...)[1]{1}
// TAILLE DATA (...)[2]{8}
// DATA (...)[11]{TAILLE DATA}
namespace Network {

    typedef enum PACKET_TYPE {
        AUTH,
        DEAUTH,
        MESSAGE,
        ERROR,
        INVALID,
        CONFIRMATION,
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
        uint64_t packet_size;
    } Header, *PHeader;

    class Server;
    
    class Client {
        public:
        Client(int socket, std::vector<PMessage>* associated_messages, int unique_id, Server* server);
        ~Client();

        void recv_loop(void);
        ssize_t get_buffer_size(void) { return this->_buffer_size; }
        char* get_buffer_ptr(void) { return this->_buffer; }
        bool is_auth(void) { return this->_authenticated; }
        int get_socket(void) { return this->_socket; }

        std::string get_name(void) { return this->_name; }

        int unique_id;

        private:

        void _handleMessage(PHeader header);

        void _handleUsername(PHeader header);

        void _sendConfirmation(void);

        void _handleDeauth(PHeader header);

        bool (*check_username_function)(void);

        Server* _associated_server;

        int _socket;
        ssize_t _buffer_size;
        char* _buffer;
        std::string _name;
        bool _authenticated;
        sockaddr_in _address;
        bool run_recieve;
        std::vector<PMessage>* _associated_messages_vector;
        std::thread _recv_thread;
    };


    // Retourne un pointeur vers une structure Message. Permet l'extraction des données
    // d'un message depuis un client
    PMessage ParseMessage(Client* client, PHeader associated_header);


    // Retourne un pointeur vers une structure Header. Permet la reconnaissance du type d'un paquet.
    // Si le paquet reçu est invalide, le membre packet_type de la structure Header vaudra PACKET_TYPE::INVALID
    // @warning Pensez à désallouer la mémoire avec delete car le Header est créé avec new
    PHeader ParseHeader(char buffer[NETWORK_HEADER_SIZE]);

    char* SerializeHeader(PHeader header);

    void SendError(int socket, ERROR_TYPE error);

    class Server {
        public:
        Server(void);
        ~Server();

        bool stop(void);
        bool start(unsigned short port);

        void accept_loop();
        void treat_message_loop(bool*);
        std::vector<PMessage>* get_treated_messages(void);

        bool check_username(std::string username);

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
