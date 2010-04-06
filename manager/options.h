#ifndef _MANAGER_OPTIONS_H
#define _MANAGER_OPTIONS_H

#include <confuse.h>

const char * get_manager_optstring();
int process_manager_optchars(int);
void clear_manager_clops(void);

cfg_opt_t *get_manager_fileopts();
void validate_manager_fileopts(cfg_t *cfg);

void fill_manager_progvars(int, char **);

#endif /* _MANAGER_OPTIONS_H */
