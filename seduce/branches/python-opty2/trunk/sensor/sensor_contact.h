#ifndef _SENSOR_CONTACT_H
#define _SENSOR_CONTACT_H

#include <nids.h> /* struct tuple4 */

int new_tcp(unsigned id, const struct tuple4 *addr);
int close_tcp(unsigned id);
int tcp_data(unsigned id, const void *payload, size_t len);
int tcp_break(unsigned id);
int udp_data(const struct tuple4 *a,const void *payload, size_t l, unsigned id);


#endif /* _SENSOR_CONTACT_H */

