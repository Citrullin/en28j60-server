#include <stddef.h>

struct Configuration {
    uint8_t mac_addr[6];
    uint8_t ip_addr[4];
    uint16_t port;
};

struct Header{
    char * keys;
    char * values;
    size_t length;
};

struct Body{
    char * data;
    size_t length;
};

struct Request {
    struct Header ** header;
    struct Body ** body;
};


struct Routes {
    struct Route ** data;
    size_t length;
};

typedef struct Server{
    struct Configuration config;
    struct Routes routes;
    struct ServerUtils* utils;
    int (*start)(struct Server* self);
} Server;


typedef char* (*receiver_func_type)(struct Server* server, struct Request* request);

struct Route {
    char * endpoint;
    receiver_func_type receiver;
};

uint16_t Server__set_response_header();
uint16_t Server__set_response_body(const char response[]);
uint16_t Server__set_dynamic_response_body(char *response);
void * Server__send_response();

Server * Server__create(struct Configuration config, struct Routes routes);

void * Server__create_routes (char* endpoints[], receiver_func_type receivers[], size_t size);