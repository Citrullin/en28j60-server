#include <avr/io.h>
#include <avr/pgmspace.h>
#include <util/delay.h>
#include <stdlib.h>
#include <string.h>
#include <lib/enc28j60.h>
#include <lib/network.h>
#include <stdio.h>
#include "server_utils.h"

#include "uart.h"

int is_running;

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

#define BUFFER_SIZE 999
uint8_t buffer[BUFFER_SIZE+1],browser;
uint16_t offset;

void Server__set_response_header(){
    offset = make_tcp_data_pos(buffer,0,PSTR("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"));
}

void Server__set_response_body(const char response[]){
    offset = make_tcp_data_pos(buffer,offset,response);
}

void Server__set_dynamic_response_body(char *response){
    offset = make_tcp_data_pos_ram(buffer,offset,response);
}

void * Server__send_response(){
    tcp_ack(buffer);
    tcp_ack_with_data(buffer,offset);

    return 0;
}

void Server__print_mac(Server *self){
    writeString("Mac address: ");
    for(int i = 0; i < sizeof(self->config.ip_addr); i++){
        print_debug_int(self->config.ip_addr[i]);
        writeString(".");
    }
    writeString("\n");
}

void Server__print_ip(Server *self){
    writeString("Server IP: ");
    for(int i = 0; i < sizeof(self->config.ip_addr); i++){
        print_debug_int(self->config.ip_addr[i]);
        if(i < sizeof(self->config.ip_addr) - 1){
            writeString(".");
        }
    }
    writeString("\n");
}

void Server__print_route(struct Route* route){
    writeString("\tEndpoint: ");
    writeString(route->endpoint);
    writeString("\n");
}

void Server__print_routes(Server *self){
    writeString("DEBUG: Server has ");
    print_debug_int(self->routes.length);
    writeString(" routes. \n");

    writeString("Server Routes:");
    for(int i = 0; i < self->routes.length; i++){
        writeString("\n");
        Server__print_route(self->routes.data[i]);
    }
    writeString("\n");
}

void Server__print_port(Server *self){
    writeString("Server Port: ");
    print_debug_int(self->config.port);
    writeString("\n");
}

int Server__start(Server* self){
    writeString("Starting Server... \n");

    is_running = 1;
    uint16_t dat_p;
    CLKPR = (1<<CLKPCE);
    CLKPR = 0;
    _delay_loop_1(50);
    ENC28J60_Init(self->config.mac_addr);
    ENC28J60_ClkOut(2);
    _delay_loop_1(50);
    ENC28J60_PhyWrite(PHLCON,0x0476);
    _delay_loop_1(50);
    init_network(self->config.mac_addr, self->config.ip_addr, self->config.port);

    Server__print_ip(self);
    Server__print_port(self);
    Server__print_routes(self);


    while(is_running) {
        offset = ENC28J60_PacketReceive(BUFFER_SIZE,buffer);
        if(offset==0) continue;
        if(eth_is_arp(buffer,offset)) {
            arp_reply(buffer);
            continue;
        }
        if(eth_is_ip(buffer,offset)==0) continue;
        if(buffer[IP_PROTO]==IP_ICMP && buffer[ICMP_TYPE]==ICMP_REQUEST) {
            icmp_reply(buffer,offset);
            continue;
        }
        if(buffer[IP_PROTO]==IP_TCP && buffer[TCP_DST_PORT]==0 && buffer[TCP_DST_PORT+1]==self->config.port) {
            if(buffer[TCP_FLAGS] & TCP_SYN) {
                tcp_synack(buffer);
                continue;
            }
            if(buffer[TCP_FLAGS] & TCP_ACK) {
                init_len_info(buffer);
                dat_p = get_tcp_data_ptr();
                if(dat_p==0) {
                    if(buffer[TCP_FLAGS] & TCP_FIN) tcp_ack(buffer);
                    continue;
                }

                if(strstr((char*) &(buffer[dat_p]),"User Agent")) browser=0;
                else if(strstr((char*) &(buffer[dat_p]),"MSIE")) browser=1;
                else browser=2;

                for(int i = 0; i < self->routes.length; i++){
                    if(strncmp(self->routes.data[i]->endpoint ,(char*)&(buffer[dat_p+4]),2)==0){
                        struct Request request = {};
                        char* response = self->routes.data[i]->receiver(self, &request);
                        Server__set_response_header();
                        Server__set_dynamic_response_body(response);
                        Server__send_response();
                        continue;
                    }
                }
            }
        }
    }

    return 0;
}

void Server__init(struct Server * self, struct Configuration config, struct Routes routes){
    self->config = config;
    self->start = &Server__start;
    self->routes = routes;
    self->utils = getServerUtils();
}

Server* Server__create(struct Configuration config, struct Routes routes){
    writeString("DEBUG: Creating Server...\n");

    writeString("DEBUG: Allocation of Server memory.\n");
    Server* server = (Server*) malloc(sizeof(Server));

    writeString("DEBUG: Init server... \n");
    Server__init(server, config, routes);

    writeString("DEBUG: Server created.\n");

    return server;
}

struct Routes* Server__create_routes (char* endpoints[], receiver_func_type receivers[], size_t size){
    writeString("DEBUG: Creating ");
    print_debug_int(size);
    writeString(" Routes\n");

    writeString("DEBUG: Reserve memory for Routes \n");
    struct Routes* routes = (struct Routes*) malloc(sizeof(struct Routes));
    routes->length = (size_t) malloc(sizeof(size_t));
    routes->data = (struct Route **) malloc(size * sizeof(struct Route));

    routes->length = size;

    for(int i = 0; i < size; i++){
        writeString("DEBUG: Create Route for endpoint ");
        writeString(endpoints[i]);
        writeString("\n");

        struct Route route = {.endpoint = endpoints[i], .receiver = receivers[i]};
        routes->data[i] = (struct Route*) malloc(sizeof(route));
        *routes->data[i] = route;

        writeString("DEBUG: Route for endpoint ");
        writeString(endpoints[i]);
        writeString("created. \n");
    }

    writeString("DEBUG: Created all routes. \n");

    return routes;
}

void * Server__create_route(char * endpoint, receiver_func_type receiver){
    struct Route* route = (struct Route*) malloc(sizeof(route));
    route->endpoint = endpoint;
    route->receiver = receiver;

    return 0;
}
