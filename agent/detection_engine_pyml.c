#include <Python.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "detection_engine.h"
#include "utils.h"

/* function prototypes */

int pyml_engine_init(void);
int pyml_engine_process(char *, size_t, Threat *);
void pyml_engine_reset(void);
void pyml_engine_destroy(void);

DetectionEngine pyml_engine = {
    .name = "pyml",
    .descr = "Behavior Testing with Neural Networks for SEDUCE",
    .init = &pyml_engine_init,
    .destroy = &pyml_engine_destroy,
    .reset = &pyml_engine_reset,
    .process = &pyml_engine_process
};

PyObject *main_function = NULL;

int pyml_engine_init(void) 
{
    PyObject *pName, *pModule, *pDict, *sys_path, *path, *site_packages_path;
    
    Py_Initialize();
    sys_path = PySys_GetObject("path");

    // Add the path to the virtual environment's site-packages
    site_packages_path = PyUnicode_FromString("agent/behaviour/pyml_venv/lib/python3.10/site-packages");

    PyList_Append(sys_path, site_packages_path);
    Py_DECREF(site_packages_path);
  
    // Set the VIRTUAL_ENV environment variable
    if (setenv("VIRTUAL_ENV", "agent/behaviour/pyml_venv", 1) != 0) {
        perror("Error while setting VIRTUAL_ENV environment variable\n");
        exit(1);
    }

    path = PyUnicode_FromString("agent/behaviour");
    PyList_Append(sys_path, path);
    Py_DECREF(path);

    pName = PyUnicode_FromString("main");

    if (!pName) {
        perror("Error while creating Python string");
        exit(1);
    }

    pModule = PyImport_Import(pName);
    if (!pModule) {
        PyErr_Print();
        perror("Error while loading Python Module!\n");
        Py_DECREF(pName);
        exit(1);
    }

    pDict = PyModule_GetDict(pModule);
    main_function = PyDict_GetItemString(pDict, "main");    
    
    if (!PyCallable_Check(main_function)) {
        perror("the main python symbol is not callable!");
        Py_DECREF(pName);
        Py_DECREF(pModule);
        exit(1);
    }

    Py_DECREF(pName);
    Py_DECREF(pModule);
    Py_DECREF(pDict);
    
    return 1;
}

int pyml_engine_process(char *data, size_t len, Threat * threat) 
{
    const char *p;
    int block_size, bytesNum, block_num = 0;
    void *block;
    char threat_msg[51] = "";
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
        PyTuple_SetItem(pArgs, 0, PyUnicode_FromString(block));

        pValue = PyObject_CallObject(main_function, pArgs);
        Py_DECREF(pArgs);

        if (pValue == NULL) {
            PyErr_Print();
            free(block);
            return -1;
        }

        bytesNum = PyLong_AsLong(pValue);
        Py_DECREF(pValue);
        if (bytesNum) {
            threat->payload = block;
            threat->length = block_size;
            threat->severity = SEVERITY_HIGH;
            if (bytesNum == 1) {
                snprintf(threat_msg, 50,
                    "XSS Detected at block %i !", 
                    block_num);
            } else if (bytesNum == 2) {
                snprintf(threat_msg, 50,
                    "SQLi Detected at block %i !",
                    block_num);
            } else if (bytesNum == 3) {
                snprintf(threat_msg, 50,
                    "Command Injection Detected at block %i !",
                    block_num);
            }
            threat->msg = strdup(threat_msg);
            return 1;
        }
        free(block);
    }
    return 0;
}

void pyml_engine_reset(void) 
{
    return;
}

void pyml_engine_destroy(void) 
{
    if (main_function)
        Py_DECREF(main_function);

    /* Terminate the Python interpreter */
    Py_Finalize();

    return;
}
