/* 
 Static Analyser for Opty2 Multibyte Nopsled Generator of Metasploit 
 15-7-2009 by Spyridon Panagiotopoulos
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "utils.h"
#include "detect_engine.h"

#include "Python.h"

/* function declarations */
int opty2Detector(char *, size_t, Threat *);
/* */

int opty2Detector(char *data, size_t len, Threat *threat)
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
            
            int bytesNum = PyInt_AsLong(pValue);
            
			if (bytesNum > 9 )
			{
			    threat->payload = block;
			    threat->length = block_size;
			    threat->severity = SEVERITY_HIGH;
			    snprintf(threat_msg, 50, "Opty2 Detected at block %i !", block_num);
                threat->msg = strdup(threat_msg);
                return 1;
            }
        }  
        free(block);
        
        Py_DECREF(pModule);  // clean up
        Py_DECREF(pName);     
	} 
}   
