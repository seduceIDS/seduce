/* 
 Python Extension For SEDUCE
 15-7-2009
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "utils.h"
#include "detect_engine.h"

#include "Python.h"

/* function prototypes */

int python_engine_init(void);
int python_engine_process(char *, size_t, Threat *);
void python_engine_reset(void);
void python_engine_destroy(void);

DetectEngine engine = {
	.name = "Python Extensions detection Engine",
	.init = &python_engine_init,
	.destroy = &python_engine_destroy,
	.reset = &python_engine_reset,
	.process = &python_engine_process
};

int python_engine_init(void) 
{
    Py_Initialize();

    PyRun_SimpleString("import os");
    PyRun_SimpleString("curDir = os.getcwd()");
    PyRun_SimpleString("import sys"); 
    PyRun_SimpleString("sys.path.append(curDir)"); 

	return 1;
}

int python_engine_process(char *data, size_t len, Threat *threat)
{
    int result = opty2Detector(data,len,threat);  // calls the opty2 nopsled detector

	return result;
}

void python_engine_reset(void)
{
	return;
}

void python_engine_destroy(void)
{
    // Finish the Python Interpreter

    Py_Finalize();
	return;	
}


