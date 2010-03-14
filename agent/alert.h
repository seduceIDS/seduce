#ifndef _ALERT_H
#define _ALERT_H

#include "manager_protocol.h"
#include "detection_engine.h"

int submit_alert(const ManagerSession *, const ConnectionInfo *, const Threat *);

#endif /* _ALERT_H */
