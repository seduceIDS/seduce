#ifndef _ITEM_SELECTION_H
#define _ITEM_SELECTION_H 	1

typedef enum { ROUND_ROBIN, RANDOM } SelectionType;
typedef void *(*SelectionMethod)(int, void *, int);

/* round robin item selection */
void *round_robin_selection(int num_items, void *items, int item_size);

/* random item selection */
void *random_selection(int num_items, void *items, int item_size);

#endif
