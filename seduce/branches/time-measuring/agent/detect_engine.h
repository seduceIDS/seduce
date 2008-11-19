#ifndef _DETECT_ENGINE_H
#define _DETECT_ENGINE_H

#include <stddef.h> /* for size_t */

#define	SEVERITY_HIGH	1
#define	SEVERITY_MEDIUM 2
#define	SEVERITY_LOW	3
#define	SEVERITY_INFO	4

typedef struct _Threat{
	unsigned char *payload;	/* The payload that caused the alert */
	size_t length;		/* The length of the payload */
	unsigned short severity;/* Severity of the threat */
	char *msg;		/* Null-Terminated, human-readable, message */
} Threat;

typedef struct _DetectEngine{
	const char *name;
	int  (*init)(void); 			/* Returns 0 on failure */
	void (*destroy)(void);
	void (*reset)(void);
	int  (*process)(char *, size_t, Threat *); /* Returns -1 on failure,
						      1 on threat detection,
						      0 otherwise */
	void *params;
} DetectEngine;

/* Function Declarations */

void destroy_threat(Threat *);
const char *get_next_block(const char *data, size_t len, int min_len, 
			   int *block_len, int use_previous_data);

#endif /* _DETECT_ENGINE_H*/
