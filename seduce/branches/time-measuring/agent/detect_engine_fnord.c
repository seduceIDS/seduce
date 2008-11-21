/* 
 fnord detection engine
 Based on Dragos Ruiu's fnord plugin (rev1.9 snort cvs)
 Incorporated into seduce by Dimitris Glynos (c) 2008
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "utils.h"
#include "detect_engine.h"

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
 * NOP Equivalent opcodes for shellcodes - Canonical List
 *
 * Arch  Code (hex, 00=wild)       Opcode
 * ----  -----------------         ---------------------
 * HPPA   08 21 02 9a               xor %r1,%r1,%r26        
 * HPPA   08 41 02 83               xor %r1,%r2,%r3         
 * HPPA   08 a4 02 46               or  %r4,%r5,%r6         
 * HPPA   09 04 06 8f               shladd %r4,2,%r8,%r15   
 * HPPA   09 09 04 07               sub %r9,%r8,%r7         
 * HPPA   09 6a 02 8c               xor %r10,%r11,%12       
 * HPPA   09 cd 06 0f               add %r13,%r14,%r15      
 * Sprc   20 bf bf 00               bn -random        
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
 * Sprc   81 d0 20 00               tn random         
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
 * Sprc   89 a5 08 22               fadds %f20,%f2,%f4
 * IA32   8c c0                     mov %es,%eax   
 * IA32   8c e0                     mov %fs,%eax   
 * IA32   8c e8                     mov %gs,%eax   
 * IA32   90                        regular NOP    
 * IA32   91                        xchg %eax,%ecx 
 * IA32   92                        xchg %eax,%edx 
 * IA32   93                        xchg %eax,%ebx 
 * HPPA   94 6c e0 84               subi,OD  42,%r3,%r12   
 * IA32   95                        xchg %eax,%ebp 
 * IA32   96                        xchg %eax,%esi 
 * Sprc   96 23 60 00               sub %o5, 42,%o3  
 * Sprc   96 24 80 12               sub %l2,%l2,%o3   
 * IA32   97                        xchg %eax,%edi 
 * IA32   98                        cwtl           
 * Sprc   98 3e 80 12               xnor %i2,%l2,%o4  
 * IA32   99                        cltd           
 * IA32   9b                        fwait          
 * IA32   9c                        pushf          
 * IA32   9e                        safh           
 * IA32   9f                        lahf           
 * Sprc   a0 26 e0 00               sub %i3, 42,%l0  
 * Sprc   a2 03 40 12               add %o5,%l2,%l1   
 * Sprc   a2 0e 80 13               and %i2,%l3,%l1   
 * Sprc   a2 1a 40 0a               xor %o1,%o2,%l1   
 * Sprc   a2 1c 80 12               xor %l2,%l2,%l1   
 * Sprc   a4 04 e0 00               add %l3, 42,%l2  
 * Sprc   a4 27 40 12               sub %i5,%l2,%l2   
 * Sprc   a4 32 a0 00               orn %o2, 42,%l2  
 * IA32   b0 00                     mov N,%eax     
 * Sprc   b2 03 60 00               add %o5, 42,%i1  
 * Sprc   b2 26 80 19               sub %i2,%i1,%i1   
 * HPPA   b5 03 e0 00               addi,OD  42,%r8,%r3    
 * HPPA   b5 4b e0 00               addi,OD  42,%r10,%r11  
 * Sprc   b6 06 40 1a               add %i1,%i2,%i3   
 * Sprc   b6 16 40 1a               or  %i1,%i2,%i3   
 * Sprc   b6 04 80 12               add %l2,%l2,%i3   
 * Sprc   b6 03 60 00               add %o5, 42,%i3  
 * Sprc   ba 56 a0 00               umul %i2, 42,%i5 
 * IA32   c1 c0 00                  rol N,%eax     
 * IA32   c1 c8 00                  ror N,%eax     
 * IA32   c1 e8 00                  shr N,%eax     
 * HPPA   d0 e8 0a e9               shrpw %r8,%r7,8,%r9     
 * IA32   f5                        cmc            
 * IA32   f7 d0                     not %eax       
 * IA32   f8                        clc            
 * IA32   f9                        stc            
 * IA32   fc                        cld            
 * 
 */

#define MAXNOP 		128 /* must be multiple of 4 (?) */
#define MAXFUZZ 	3
#define SKIP 		0
#define BACKTRACK 	1
#define SKIPIA32 	11
#define SKIPHPPA 	12
#define SKIPSPARC 	13
#define WALK 		20
#define WALKIA32 	21
#define WALKHPPA 	22
#define WALKSPARC 	23

#define VAL 		(*pointer)
#define CMP(x) 		(*pointer == x)
#define CMPL(l,x) 	(*(pointer+l) == x)
#define CMP2(x,y) 	((*pointer == x) && (*(pointer+1) == y))
#define CMPL2(l,x,y) 	((*(pointer+l) == x) && (*(pointer+l+1) == y))
#define CMP3(x,y,z) 	((*pointer == x) && (*(pointer+1) == y) && \
		    	(*(pointer+2) == z))
#define CMPL3(l,x,y,z) 	((*(pointer+l) == x) && (*(pointer+l+1) == y) && \
		    	(*(pointer+l+2) == z))
#define CMP4(x,y,z,q) 	((*pointer == x) && (*(pointer+1) == y) && \
			(*(pointer+2) == z) && (*(pointer+3) == q))
#define CMPL4(l,x,y,z,q) ((*(pointer+l) == x) && (*(pointer+l+1) == y) && \
			(*(pointer+l+2) == z) && (*(pointer+l+3) == q))
#define INC(val) 	((pointer < (max - val)) ? (pointer += val) : \
			(pointer = max))

#define FOUND_IA32 	1
#define FOUND_HPPA 	2
#define FOUND_SPARC 	3

static void prepare_nopsled_threat(char *type /* IA32 / HPPA / Sparc */, 
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
	register unsigned char *pstart;
	register unsigned char *max;
	register unsigned char *pointer;
	int fuzz, len, mode;

        pstart = data;
        pointer = pstart;
        max = pstart + plen - 4;
        mode = SKIP;
        fuzz = 0;
        len = 0;

        while(pointer < max)
        {
		/*
		DPRINTF("pointer: %08X max: %08X count: %d "
			"val: %02X %02X %02X %02X "
			"len: %d mode: %d fuzz: %d\n",
			pointer, max, (plen - (max - pointer)),
			VAL, *(pointer+1), *(pointer+2), *(pointer+3),
			len, mode, fuzz);
		*/

                /* SPARC 4 byte nop detector */
                /* note it is important to check these before intel 
		 * because 0x96 and 0x98 overlap */
                if(
			CMP3(0x20,0xBF,0xBF) || /* bn -random */
                        CMP3(0x81,0xD0,0x20) || /* tn random */
                        CMP4(0x89,0xA5,0x08,0x22) || /* fadds %f20,%f2,%f4*/
                        (CMP(0x96) &&
                          ( CMPL2(1,0x23,0x60) || /* sub %o5,0x42,%o3 */
                            CMPL3(1,0x24,0x80,0x12))) || /* sub %l2,%l2,%o3 */
                        CMP4(0x98,0x3E,0x80,0x12) || /* xnor %i2,%l2,%o4 */
                        CMP3(0xA0,0x26,0xE0) || /* sub %i3,0x42,%l0 */
                        (CMP(0xA2) &&
                          ( CMPL3(1,0x03,0x40,0x12) || /* add %o5,%l2,%l1 */
                            CMPL3(1,0x0E,0x80,0x13) || /* and %i2,%l3,%l1 */
                            CMPL3(1,0x1A,0x40,0x0A) || /* xor %o1,%o2,%l1 */
                            CMPL3(1,0x1C,0x80,0x12))) || /* xor %l2,%l2,%l1 */
                        (CMP(0xA4) &&
                          ( CMPL2(1,0x04,0xE0) || /* add %l3,0x42,%l2 */
                            CMPL3(1,0x27,0x40,0x12) || /* sub %i5,%l2,%l2 */
                            CMPL2(1,0x32,0xA0))) || /* orn %o2,0x42,%l2 */
                        (CMP(0xB2) &&
                          ( CMPL2(1,0x03,0x60) || /* add %o5,0x42,%i1 */
                            CMPL3(1,0x26,0x80,0x19))) || /* sub %i2,%i1,%i1 */
                        (CMP(0xB6) &&
                          ( CMPL3(1,0x06,0x40,0x1A) || /* add %i1,%i2,%i3 */
                            CMPL3(1,0x16,0x40,0x1A) || /* or %i1,%i2,%i3 */
                            CMPL3(1,0x04,0x80,0x12) || /* add %l2,%l2,%i3 */
                            CMPL2(1,0x03,0x60))) || /* add %o5,0x42,%i3 */
                        CMP3(0xBA,0x56,0xA0) /* umul %i2,0x42,%i5 */
		)
                {
			if(mode == SKIP)
                        {
                                mode = BACKTRACK;
                                INC(0 - (fuzz + MAXNOP));
                        }
                        else if(mode == WALKSPARC)
                        {
                                len += 4;
                                INC(4);
                        }
                        else if(mode == SKIPSPARC)
                        {
                                mode = WALKSPARC;
                                INC( - MAXNOP);
                        }
                        else
                        {
                                mode = SKIPSPARC;
                                len = 0;
                                fuzz = 0;
                                INC(MAXNOP);
                        }
                }

                /* HPPA nop detector */
                else if(
			(CMP(0x08) &&
                          ( CMPL3(1,0x21,0x02,0x9A) || /* xor %r1,%r1,%r26 */
                            CMPL3(1,0x41,0x02,0x83) || /* xor %r1,%r2,%r3 */
                            CMPL3(1,0xA4,0x02,0x46))) || /* or %r4,%r5,%r6 */
                        (CMP(0x09) &&
                          ( CMPL3(1,0x04,0x06,0x8F) || /*shladd %r4,2,%r8,%r15*/
                            CMPL3(1,0x09,0x04,0x07) || /* sub %r9,%r8,%r7 */
                            CMPL3(1,0x6A,0x02,0x8C) || /* xor %r10,%r11,%12 */
                            CMPL3(1,0xCD,0x06,0x0F))) || /* add %r13,%r14,%r15*/
                        CMP4(0x94,0x6C,0xE0,0x84) || /* subi,OD 0x42,%r3,%r12 */
                        CMP4(0xD0,0xE8,0x0A,0xE9) || /* shrpw %r8,%r7,8,%r9 */
                        (CMP(0xB5) &&
                          ( CMPL2(1,0x03,0xE0) || /* addi,OD 0x42,%r8,%r3 */
                            CMPL2(1,0x4B,0xE0))) /* addi,OD 0x42,%r10,%r11 */
                )
                {
                        if(mode == SKIP)
                        {
                                mode = BACKTRACK;
                                INC(0 - (fuzz + MAXNOP));
                        }
                        else if(mode == WALKHPPA)
                        {
                                len += 4;
                                INC(4);
                        }
                        else if(mode == SKIPHPPA)
                        {
                                mode = WALKHPPA;
                                INC( - MAXNOP);
                        }
                        else
                        {
                                mode = SKIPHPPA;
                                len = 0;
                                fuzz = 0;
                                INC(MAXNOP);
                        }
                }

                /* intel 3 byte with wildcard nop codes */
                else if(
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
                        if(mode == SKIP)
                        {
                                mode = BACKTRACK;
                                INC(0 - (fuzz + MAXNOP));
                        }
                        else if(mode == WALKIA32)
                        {
                                len += 3;
                                INC(3);
                        }
                        else if(mode == SKIPIA32)
                        {
                                mode = WALKIA32;
                                INC(0 - (fuzz + MAXNOP));
                        }
                        else
                        {
                                mode = SKIPIA32;
                                len = 0;
                                fuzz = 0;
                                INC(MAXNOP);
                        }
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
                        if(mode == SKIP)
                        {
                                mode = BACKTRACK;
                                INC(0 - (fuzz + MAXNOP));
                        }
                        else if(mode == WALKIA32)
                        {
                                len += 2;
                                INC(2);
                        }
                        else if(mode == SKIPIA32)
                        {
                                mode = WALKIA32;
                                INC(0 - (fuzz + MAXNOP));
                        }
                        else
                        {
                                mode = SKIPIA32;
                                len = 0;
                                fuzz = 0;
                                INC(MAXNOP);
                        }
                }

                /* one byte intel nop detector */

                else if(
                    ((VAL >= 0x3f) && (VAL <=0x60)) || /* inc, dec, push, pop */
                    ((VAL >= 0x90) && (VAL <=0x9F)) || /* nop, xchg, cwtl, 
							  fwait, pushf safh,
							  lahf */
                    CMP(0x27) || /* daa "'" */
                    CMP(0x2F) || /* das "/" */
                    CMP(0x37) || /* aaa "7" */
                    CMP(0x60) || /* pusha "`" */
                    CMP(0xF5) || /* cmc */
                    CMP(0xF8) || /* clc */
                    CMP(0xF9) || /* stc */
                    CMP(0xFC) 	 /* cld */
                )
                {
                        if(mode == SKIP)
                        {
                                mode = BACKTRACK;
                                INC(0 - (fuzz + MAXNOP));
                        }
                        else if(mode == WALKIA32)
                        {
                                len += 1;
                                INC(1);
                        }
                        else if(mode == SKIPIA32)
                        {
                                mode = WALKIA32;
                                INC(0 - (fuzz + MAXNOP));
                        }
                        else
                        {
                                mode = SKIPIA32;
                                len = 0;
                                fuzz = 0;
                                INC(MAXNOP);
                        }
                }
                else
                { /* NO NOP CODE */
                        if(mode == BACKTRACK)
                        {
                                INC(1);
                        }
                        else if(mode >= WALK)
                        {
                                mode = SKIP;
                                INC(MAXNOP);
                                fuzz = 0;
                        }
                        else
                        {
                                if(fuzz > MAXFUZZ || mode == SKIPHPPA || mode == SKIPSPARC)
                                {
                                        mode = SKIP;
                                        INC(MAXNOP - fuzz);
                                        fuzz = 0;
                                }
                                else
                                { /* only fuzz for SKIP and SKIPIA32 */
                                        fuzz++;
                                        INC(1);
                                }
                        }
                }

                if( len >= MAXNOP )
                {
			switch(mode) {
				case WALKIA32:
					return FOUND_IA32;
				case WALKHPPA:
					return FOUND_HPPA;
				case WALKSPARC:
					return FOUND_SPARC;
			}
			/* no real point in checking further */
			pointer = max;
                }
        }
	return 0;
}

int fnord_engine_init(void) 
{
	return 1;
}

int fnord_engine_process(char *data, size_t len, Threat *t)
{
	const char *p;
	int nop, block_size, block_num = 0;
	void *block;

	if((data == NULL) || (len == 0))
		return 0;

	while((p = get_next_block(data, len, MIN_BLOCK_LENGTH, &block_size,
				  block_num++))) 
	{
		block = malloc(block_size);
		if (block == NULL) {
			perror("malloc failed while building block\n");
			return -1;
		}

		memcpy(block, p, block_size);

		nop = fnord_test(data, len);
	
		switch(nop) {
		case FOUND_SPARC:
			prepare_nopsled_threat(	"SPARC", block, block_size,
						block_num, t);
			return 1;
		case FOUND_HPPA:
			prepare_nopsled_threat( "HPPA", block, block_size,
						block_num, t);
			return 1;
		case FOUND_IA32:
			prepare_nopsled_threat( "IA32", block, block_size,
						block_num, t);
			return 1;
		default:
			free(block);
			break;
		}
	}
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


