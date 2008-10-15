#ifndef _SERVER_CONTACT_H
#define _SERVER_CONTACT_H

int server_connect(in_addr_t addr, unsigned short port);
int server_disconnect(void);
int new_tcp_connection(unsigned id, const struct tuple4 *conn);
int close_tcp_connection(unsigned id);
int send_tcp_data(unsigned id, const void *data, size_t len);
int tcp_data_break(unsigned id);
int send_udp_data(const struct tuple4 *conn, const void *data,
						size_t len, unsigned id);

#endif /* _SERVER_CONTACT_H */
