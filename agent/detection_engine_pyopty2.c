/* 
 * SEDUCE detection of metasploit opty2 nopsled (using Python)
 */

#include <Python.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "detection_engine.h"
#include "utils.h"

/* function prototypes */

int pyopty2_engine_init(void);
int pyopty2_engine_process(char *, size_t, Threat *);
void pyopty2_engine_reset(void);
void pyopty2_engine_destroy(void);

DetectionEngine pyopty2_engine = {
	.name = "pyopty2",
	.descr = "Opty2 Detection Engine (uses Python)",
	.init = &pyopty2_engine_init,
	.destroy = &pyopty2_engine_destroy,
	.reset = &pyopty2_engine_reset,
	.process = &pyopty2_engine_process
};

static PyObject *scanner = NULL;

int pyopty2_engine_init(void) 
{
	PyObject *pName, *pModule, *pDict;

	Py_Initialize();

	pName = PyString_FromString("detection_engine_pyopty2");

	if (!pName) {
		perror("Error while creating Python string");
		exit(1);
	}

	pModule = PyImport_Import(pName);
	if (!pModule) {
		perror("Error while loading Python Module!\n");
		exit(1);
	}

	pDict = PyModule_GetDict(pModule);
	scanner = PyDict_GetItemString(pDict, "do_opty2_scan");
	
	if (!PyCallable_Check(scanner)) {
		perror("the do_opty2_scan python symbol is not callable!");
		exit(1);
	}

	Py_DECREF(pName);
	Py_DECREF(pModule);
	Py_DECREF(pDict);
	
	return 1;
}

int pyopty2_engine_process(char *data, size_t len, Threat * threat) 
{
	const char *p;
	int block_size, bytesNum, block_num = 0;
	void *block;
	char threat_msg[51];
	PyObject *pValue, *pArgs;

	if ((data == NULL) || (len == 0))
		return 0;

	while ((p = get_next_block(data, len, MIN_BLOCK_LENGTH, &block_size,
				   block_num++)))
	{
		block = malloc(block_size);
		if (block == NULL) {
			perror("malloc failed while building block\n");
			return -1;
		}

		memcpy(block, p, block_size);

		pArgs = PyTuple_New(1);
		PyTuple_SetItem(pArgs, 0, PyString_FromString(block));

		pValue = PyObject_CallObject(scanner, pArgs);
		Py_DECREF(pArgs);

		bytesNum = PyInt_AsLong(pValue);
		Py_DECREF(pValue);

		if (bytesNum > 9) {
			threat->payload = block;
			threat->length = block_size;
			threat->severity = SEVERITY_HIGH;
			snprintf(threat_msg, 50,
				 "Opty2 Nops Detected at block %i !",
				 block_num);
			threat->msg = strdup(threat_msg);
			return 1;
		}
		free(block);
	}
	return 0;
}

void pyopty2_engine_reset(void) 
{
	return;
}

void pyopty2_engine_destroy(void) 
{
	if (scanner)
		Py_DECREF(scanner);

	/* Terminate the Python interpreter */
	Py_Finalize();

	return;
}
