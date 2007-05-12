#ifndef _SENSOR_H
#define _SENSOR_H

 /* struct filled with command-line arguments */
typedef struct _CommandLineOptions {
	char *server;
	char *portlist_expr;
	char *homenet_expr;
	char *interface;
	char *conf_file;
} CommandLineOptions;

/* Program variables */
typedef struct _progvars {
	char *prog_name;
	in_addr_t server_addr;
	unsigned short server_port;
	u_int8_t port_table[65536];
} PV;

extern PV pv;

#define TCP_PORT	1
#define UDP_PORT	2


#endif /* _SENSOR_H */
