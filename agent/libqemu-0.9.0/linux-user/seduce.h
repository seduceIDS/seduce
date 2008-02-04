
#define SYSTEM_CALL         1000
#define EXCEPTION_INTERRUPT 1001
#define EXCEPTION_NOSEG     1002
#define EXCEPTION_STACK     1003
#define EXCEPTION_GPF       1004
#define EXCEPTION_PAGE      1005
#define EXCEPTION_DIVZ      1006
#define EXCEPTION_SSTP      1007
#define EXCEPTION_INT3      1008
#define EXCEPTION_INTO      1009
#define EXCEPTION_BOUND     1010
#define EXCEPTION_ILLOP     1011
#define EXCEPTION_DEBUG     1012
#define UNKNOWN_EXCEPTION   1013

int qemu_exec(void *data, size_t len, unsigned long stack_base, CPUX86State *env);
unsigned long setup_stack(void);

