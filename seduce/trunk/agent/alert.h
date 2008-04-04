#ifndef _ALERT_H
#define _ALERT_H

#include "server_contact.h"
#include "detect_engine.h"

int alert_submission(ConnectionInfo *c, Threat *t);

#endif /* _ALERT_H */
