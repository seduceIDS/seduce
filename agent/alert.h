#ifndef _ALERT_H
#define _ALERT_H	1

#include "sensor_contact.h"
#include "detect_engine.h"

int submit_alert(const SensorSession *, const ConnectionInfo *,const Threat *);

#endif /* _ALERT_H */
