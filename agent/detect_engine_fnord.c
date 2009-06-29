/* 
 fnord-like detection engine
 Based on Dragos Ruiu's fnord plugin (rev1.9 snort cvs)
 Incorporated into seduce by Dimitris Glynos (c) 2008
 Updated with list of extra single byte NOPs found in metasploit framework 
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "utils.h"
#include "detect_engine.h"

#include </usr/include/python2.5/Python.h>

/* minimum number of bytes that is considered a nop sled */
#define MAXNOP 		128

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

/*
 * NOP Equivalent opcodes for x86 shellcodes - Canonical List
 *
 * Arch  Code (hex, 00=wild)       Opcode
 * ----  -----------------         ---------------------
 * IA32	  06			    push es	(ADDED)
 * IA32	  0e			    push cs	(ADDED)
 * IA32   16			    push ss	(ADDED)
 * IA32   1e			    push ds	(ADDED)
 * IA32   27                        daa                           ' 
 * IA32   2f                        das                           /
 * IA32   33 c0                     xor %eax,%eax  
 * IA32   37                        aaa                           7 
 * IA32   3f                        aas                           ? 
 * IA32   40                        inc %eax                      @ 
 * IA32   41                        inc %ecx                      A 
 * IA32   42                        inc %edx                      B 
 * IA32   43                        inc %ebx                      C 
 * IA32   44                        inc %esp                      D 
 * IA32   45                        inc %ebp                      E 
 * IA32   46                        inc %esi                      F 
 * IA32   47                        inc %edi                      G 
 * IA32   48                        dec %eax,                     H 
 * IA32   4a                        dec %edx                      J 
 * IA32   4b                        dec %ebx                      K 
 * IA32   4c                        dec %esp                      L 
 * IA32   4d                        dec %ebp,                     M 
 * IA32   4e                        dec %esi                      N 
 * IA32   4f                        dec %edi                      O 
 * IA32   50                        push %eax                     P 
 * IA32   51                        push %ecx                     Q 
 * IA32   52                        push %edx                     R 
 * IA32   53                        push %ebx                     S 
 * IA32   54                        push %dsp                     T 
 * IA32   55                        push %ebp                     U 
 * IA32   56                        push %esi                     V 
 * IA32   57                        push %edi                     W 
 * IA32   58                        pop %eax                      X 
 * IA32   59                        pop %ecx                      Y 
 * IA32   5a                        pop %edx                      Z 
 * IA32   5b                        pop %ebx                      [ 
 * IA32   5d                        pop %ebp                      ] 
 * IA32   5e                        pop %esi                      ^ 
 * IA32   5f                        pop %edi                      _ 
 * IA32   60                        pusha                         ` 
 * IA32   6b c0 00                  imul N,%eax    
 * IA32   83 e0 00                  and N,%eax     
 * IA32   83 c8 00                  or  N,%eax     
 * IA32   83 e8 00                  sub N,%eax     
 * IA32   83 f0 00                  xor N,%eax     
 * IA32   83 f8 00                  cmp N,%eax     
 * IA32   83 f9 00                  cmp N,%ecx     
 * IA32   83 fa 00                  cmp N,%edx     
 * IA32   83 fb 00                  cmp N,%ebx     
 * IA32   83 c0 00                  add N,%eax     
 * IA32   85 c0                     test %eax,%eax 
 * IA32   87 d2                     xchg %edx,%edx 
 * IA32   87 db                     xchg %ebx,%ebx 
 * IA32   87 c9                     xchg %ecx,%ecx 
 * IA32   8c c0                     mov %es,%eax   
 * IA32   8c e0                     mov %fs,%eax   
 * IA32   8c e8                     mov %gs,%eax   
 * IA32   90                        regular NOP    
 * IA32   91                        xchg %eax,%ecx 
 * IA32   92                        xchg %eax,%edx 
 * IA32   93                        xchg %eax,%ebx 
 * IA32   95                        xchg %eax,%ebp 
 * IA32   96                        xchg %eax,%esi 
 * IA32   97                        xchg %eax,%edi 
 * IA32   98                        cwtl           
 * IA32   99                        cltd           
 * IA32   9b                        fwait          
 * IA32   9c                        pushf          
 * IA32   9e                        safh           
 * IA32   9f                        lahf           
 * IA32   b0 00                     mov N,%eax     
 * IA32   c1 c0 00                  rol N,%eax     
 * IA32   c1 c8 00                  ror N,%eax     
 * IA32   c1 e8 00                  shr N,%eax     
 * IA32	  d6			    salc (ADDED)
 * IA32   f5                        cmc            
 * IA32   f7 d0                     not %eax       
 * IA32   f8                        clc            
 * IA32   f9                        stc            
 * IA32   fc                        cld            
 * IA32   fd			    std (ADDED)
 * 
 */


#define RESET 		0
#define WALKIA32 	1

#define NO_NOP_FOUND	0
#define FOUND_IA32 	1

#define VAL 		(*pointer)
#define CMP(x) 		(*pointer == x)
#define WITHIN_RANGE(l) ((pointer+l) <= max)
#define CMPL(l,x) 	(WITHIN_RANGE(l) && (*(pointer+l) == x))
#define CMP2(x,y) 	(WITHIN_RANGE(1) && (*pointer == x) && \
			(*(pointer+1) == y))
#define CMPL2(l,x,y) 	(WITHIN_RANGE(l+1) && (*(pointer+l) == x) && \
			(*(pointer+l+1) == y))
#define CMP3(x,y,z) 	(WITHIN_RANGE(2) && (*pointer == x) && \
			(*(pointer+1) == y) && (*(pointer+2) == z))
#define CMPL3(l,x,y,z) 	(WITHIN_RANGE(l+2) && (*(pointer+l) == x) && \
			(*(pointer+l+1) == y) && (*(pointer+l+2) == z))
#define CMP4(x,y,z,q) 	(WITHIN_RANGE(3) && (*pointer == x) && \
			(*(pointer+1) == y) && (*(pointer+2) == z) && \
			(*(pointer+3) == q))
#define CMPL4(l,x,y,z,q) (WITHIN_RANGE(l+3) && (*(pointer+l) == x) && \
			(*(pointer+l+1) == y) && (*(pointer+l+2) == z) && \
			(*(pointer+l+3) == q))

static void prepare_nopsled_threat(char *type /* IA32 / HPPA / Sparc etc. */, 
		 		   void *data, int length, int block_num, 
				   Threat *t)
{
	char threat_msg[31];

	DPRINTF("fnord detected %s nopsled in block %d\n",
		type, block_num);
	t->payload = data;
	t->length = length;
	t->severity = SEVERITY_LOW;
        snprintf(threat_msg, 30, "%s nopsled detected", type);
	t->msg = strdup(threat_msg);
}

static int fnord_test(void *data, int plen)
{
	register unsigned char *alignment;
	register unsigned char *max;
	register unsigned char *pointer;
	int len, mode;

        alignment = data;
        pointer = alignment;
        max = data + plen - 1;
        mode = RESET;
        len = 0;

	while(alignment <= max)
        {
	/*
		DPRINTF("offset:%04X pointer: %08X max: %08X alignment: %08X "
			"val: %02X %02X %02X %02X "
			"len: %d mode: %d\n",
			(unsigned int) (pointer - (unsigned char *) data),
			(unsigned int) pointer, (unsigned int) max,
			(unsigned int) alignment, 
			VAL, *(pointer+1), *(pointer+2), *(pointer+3),
			len, mode);
	*/
                /* intel 3 byte with wildcard nop codes */
                if(
			CMP2(0x6B,0xC0) || /* imul N,%eax */
                        (CMP(0x83) &&
                          ( CMPL(1,0xE0) || /* and N,%eax */
                            CMPL(1,0xC8) || /* or N,%eax */
                            CMPL(1,0xE8) || /* sub N,%eax */
                            CMPL(1,0xF0) || /* xor N,%eax */
                            CMPL(1,0xF8) || /* cmp N,%eax */
                            CMPL(1,0xF9) || /* cmp N,%ecx */
                            CMPL(1,0xFA) || /* cmp N,%edx */
                            CMPL(1,0xFB) || /* cmp N,%ebx */
                            CMPL(1,0xC0))) || /* add N,%eax, N */
                        (CMP(0xC1) &&
                          ( CMPL(1,0xC0) || /* rol N,%eax */
                            CMPL(1,0xC8) || /* ror N,%eax */
                            CMPL(1,0xE8))) /* shr N,%eax */
                )
                {
			len += 3;
			pointer += 3;

			if (mode == RESET)
				mode = WALKIA32;
		}
                /* intel 2 byte nop codes */
                else if(
			CMP2(0x33,0xC0) || /* xor %eax,%eax */
                        CMP2(0x85,0xC0) || /* test %eax,%eax */
                        (CMP(0x87) &&
                          ( CMPL(1,0xD2) || /* xchg %edx,%edx */
                            CMPL(1,0xDB) || /* xchg %ebx,%ebx */
                            CMPL(1,0xC9))) || /* xchg %ecx,%ecx */
                        (CMP(0x8C) &&
                          ( CMPL(1,0xC0) || /* mov %es,%eax */
                            CMPL(1,0xE0) || /* mov %fs,%eax */
                            CMPL(1,0xE8))) || /* mov %gs,%eax */
                        CMP(0xB0) || /* mov N,%eax */
                        CMP2(0xF7,0xD0) /* not %eax */
                )
                {
			len += 2;
			pointer += 2;

                        if(mode == RESET)
				mode = WALKIA32;
               	} else if(
                    ((VAL >= 0x3f) && (VAL <=0x60)) || /* inc, dec, push, pop */
                    ((VAL >= 0x90) && (VAL <=0x9F)) || /* nop, xchg, cwtl, 
							  fwait, pushf safh,
							  lahf */
		    CMP(0x06) || /* push es (ADDED) */
		    CMP(0x0e) || /* push cs (ADDED) */
		    CMP(0x16) || /* push ss (ADDED) */
		    CMP(0x1e) || /* push ds (ADDED) */
                    CMP(0x27) || /* daa "'" */
                    CMP(0x2F) || /* das "/" */
                    CMP(0x37) || /* aaa "7" */
                    CMP(0x60) || /* pusha "`" */
		    CMP(0xD6) || /* salc (ADDED) */
                    CMP(0xF5) || /* cmc */
                    CMP(0xF8) || /* clc */
                    CMP(0xF9) || /* stc */
                    CMP(0xFC) || /* cld */
		    CMP(0xFD)	 /* std (ADDED) */
                )
                {
			len += 1;
			pointer += 1;

			if (mode == RESET)
				mode = WALKIA32;
		}
                else
                { /* NO NOP CODE */
			alignment++;
			pointer = alignment;
			len = 0;

			if (mode == WALKIA32)
				mode = RESET;
                }

                if(len >= MAXNOP)
			return FOUND_IA32;

		if ((pointer > max) && (mode == WALKIA32)) {
			alignment++;
			pointer = alignment;
			mode = RESET;
			len = 0;
		}
	}
	return NO_NOP_FOUND;
}

int fnord_engine_init(void) 
{
	return 1;
}

int fnord_engine_process(char *data, size_t len, Threat *threat)
{
	const char *p;
	int nop, block_size, block_num = 0;
	void *block;
	char threat_msg[51];

	if((data == NULL) || (len == 0))
		return 0;

    PyObject *pName, *pModule, *pDict, *pFunc, *pValue, *pArgs;

    Py_Initialize();

    PyRun_SimpleString("import os");
    PyRun_SimpleString("curDir = os.getcwd()");
    PyRun_SimpleString("import sys"); 
    PyRun_SimpleString("sys.path.append(curDir)"); 

    pName = PyString_FromString("py_fnord");
    if (!pName)
        printf("Error Loading Python String !");
        
    pModule = PyImport_Import(pName);
    if ( !pModule ) 
        printf("Error Loading Python Module !");
        
    pDict = PyModule_GetDict(pModule);
    pFunc = PyDict_GetItemString(pDict, "fnordCheck");
    
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


