#ifndef _ALERT_H
#define _ALERT_H

#include "server_contact.h"
#include "detect_engine.h"

int submit_alert(const ServerSession *, const ConnectionInfo *,const Threat *t);

#endif /* _ALERT_H */
