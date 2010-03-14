#ifndef _ITEM_SELECTION_H
#define _ITEM_SELECTION_H 	1

typedef enum { ROUND_ROBIN, RANDOM } SelectionType;
typedef void *(*SelectionMethod) (int num_items, void *items, int item_size,
				  void **context);

/* round robin item selection */
void *round_robin_selection(int, void *, int, void **);

/* random item selection */
void *random_selection(int, void *, int, void **);

/* returns 0 if s is not a valid SelectionType option */
int is_selection_valid(SelectionType s);

#endif
