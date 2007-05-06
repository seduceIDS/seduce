#ifndef _SERVER_CONTACT_H
#define _SERVER_CONTACT_H

int server_connect(in_addr_t addr, unsigned short port);
int server_disconnect(void);
int new_tcp_connection(unsigned int id, struct tuple4 *conn);
int close_tcp_connection(unsigned int id);
int send_tcp_data(unsigned int id, u_char *data, int len);
int tcp_data_break(unsigned int id);
int send_udp_data(struct tuple4 *conn, u_char *data, int len, unsigned int id);

#endif /* _SERVER_CONTACT_H */
