#ifndef _DETECT_ENGINE_H
#define _DETECT_ENGINE_H

#include <stddef.h> /* for size_t */

typedef enum {
	SEVERITY_HIGH = 1,
	SEVERITY_MEDIUM = 2,
	SEVERITY_LOW = 3,
	SEVERITY_INFO = 4
} ImpactSeverity;

typedef struct _Threat{
	unsigned char *payload;	 /* The payload that caused the alert */
	size_t length;		 /* The length of the payload */
	ImpactSeverity severity; /* Severity of the threat */
	char *msg;		 /* Null-Terminated, human-readable, message */
} Threat;

typedef struct _DetectEngine{
	void (*init)(void);
	void (*stop)(void);
	int (*process)(char *, size_t);
	int (*get_threat)(Threat *);
} DetectEngine;


/* Function Declarations */
void destroy_threat(Threat *);

#endif /* _DETECT_ENGINE_H*/
