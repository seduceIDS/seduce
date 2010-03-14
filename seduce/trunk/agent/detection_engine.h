#ifndef _DETECTION_ENGINE_H
#define _DETECTION_ENGINE_H

#include <stddef.h> /* for size_t */

#define	SEVERITY_HIGH	1
#define	SEVERITY_MEDIUM 2
#define	SEVERITY_LOW	3
#define	SEVERITY_INFO	4

/* An engine checks only blocks that are larger or equal to MIN_BLOCK_LENGTH */

#ifdef _NO_MIN_BLOCK_LENGTH
#define MIN_BLOCK_LENGTH	1
#else
#define MIN_BLOCK_LENGTH        30
#endif

typedef struct _Threat{
	unsigned char *payload;	/* The payload that caused the alert */
	size_t length;		/* The length of the payload */
	unsigned short severity;/* Severity of the threat */
	char *msg;		/* Null-Terminated, human-readable, message */
} Threat;

typedef struct _DetectionEngine {
	char *name;
	char *descr;
	int  (*init)(void); 			/* Returns 0 on failure */
	void (*destroy)(void);
	void (*reset)(void);
	int  (*process)(char *, size_t, Threat *); /* Returns -1 on failure,
						      1 on threat detection,
						      0 otherwise */
	void *params;
} DetectionEngine;

/* Function Declarations */

void destroy_threat(Threat *);
const char *get_next_block(const char *data, size_t len, int min_len, 
			   int *block_len, int use_previous_data);
DetectionEngine *get_engine_by_name(char *name);
DetectionEngine *cycle_engines(DetectionEngine **context);
int format_engine_list(char *buf, int bufsize);
void apply_to_engines(void (*fun)(DetectionEngine *, void *), void *param);

#endif /* _DETECTION_ENGINE_H */
