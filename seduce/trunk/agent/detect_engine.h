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
	int  (*init)(void); 		/* Return 1|0 (0 on failure) */
	void (*destroy)(void);
	void (*reset)(void);
	int  (*process)(char *, size_t);/* Return 1|0|-1 (-1 on faulure) */
	int  (*get_threat)(Threat *);	/* Return 0|1 (0 on failure) */
	void *params;
} DetectEngine;


/* Function Declarations */
void destroy_threat(Threat *);

#endif /* _DETECT_ENGINE_H*/
