/* 
 fnord-like detection engine
 Based on Dragos Ruiu's fnord plugin (rev1.9 snort cvs)
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "utils.h"
#include "detect_engine.h"

#include "Python.h"

/* function prototypes */

int fnord_engine_init(void);
int fnord_engine_process(char *, size_t, Threat *);
void fnord_engine_reset(void);
void fnord_engine_destroy(void);

DetectEngine engine = {
	.name = "fnord NOP detection Engine",
	.init = &fnord_engine_init,
	.destroy = &fnord_engine_destroy,
	.reset = &fnord_engine_reset,
	.process = &fnord_engine_process
};

int fnord_engine_init(void) 
{

    Py_Initialize();

    PyRun_SimpleString("import os");
    PyRun_SimpleString("curDir = os.getcwd()");
    PyRun_SimpleString("import sys"); 
    PyRun_SimpleString("sys.path.append(curDir)"); 

	return 1;
}

int fnord_engine_process(char *data, size_t len, Threat *threat)
{
	const char *p;
	int block_size, block_num = 0;
	void *block;
	char threat_msg[51];

	if((data == NULL) || (len == 0))
		return 0;

    PyObject *pName, *pModule, *pDict, *pFunc, *pValue, *pArgs;

    pName = PyString_FromString("detect_engine_opty2");
    if (!pName)
        printf("Error Loading Python String !");
        
    pModule = PyImport_Import(pName);
    if ( !pModule ) 
        printf("Error Loading Python Module !");
        
    pDict = PyModule_GetDict(pModule);
    pFunc = PyDict_GetItemString(pDict, "opty2Check");
    
	while((p = get_next_block(data, len, MIN_BLOCK_LENGTH, &block_size,
				  block_num++))) 
	{
		block = malloc(block_size);
		if (block == NULL) {
			perror("malloc failed while building block\n");
			return -1;
		}
		
		memcpy(block, p, block_size);
		
		if (PyCallable_Check(pFunc)) 
        {
            pArgs = PyTuple_New(1);
            PyTuple_SetItem(pArgs, 0, PyString_FromString(block));  
            
            pValue = PyObject_CallObject(pFunc, pArgs);
            
            int percentage = PyInt_AsLong(pValue);

			if (percentage > 70 )
			{
			    threat->payload = block;
			    threat->length = block_size;
			    threat->severity = SEVERITY_HIGH;
			    snprintf(threat_msg, 50, "Fnord Detected at block %i !", block_num);
                threat->msg = strdup(threat_msg);
                return 1;
            }
        }  
        free(block);
        
	}    
    

    // Clean up

    Py_DECREF(pModule);
    Py_DECREF(pName);

    // Finish the Python Interpreter

    Py_Finalize();
   

	return 0;
}

void fnord_engine_reset(void)
{
	return;
}

void fnord_engine_destroy(void)
{
	return;	
}


