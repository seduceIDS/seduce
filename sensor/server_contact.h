#ifndef _SERVER_CONTACT_H
#define _SERVER_CONTACT_H

int server_connect(in_addr_t, unsigned short);
int server_disconnect(void);
int new_tcp_connection(unsigned int, struct tuple4 *);
int close_tcp_connection(unsigned int);
int send_tcp_data(unsigned int, u_char *, int);
int send_udp_data(struct tuple4 *, u_char *, int, unsigned int);

#endif /* _SERVER_CONTACT_H */
