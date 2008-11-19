#ifndef _ITEM_SELECTION_H
#define _ITEM_SELECTION_H 	1

typedef enum { ROUND_ROBIN, RANDOM } SelectionType;
typedef void *(*SelectionMethod) (int num_items, void *items, int item_size);

/* round robin item selection */
void *round_robin_selection(int, void *, int);

/* random item selection */
void *random_selection(int, void *, int);

/* returns 0 if s is not a valid SelectionType option */
int is_selection_valid(SelectionType s);

#endif
