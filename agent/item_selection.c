#include <stdlib.h>

void *random_selection(int num_items, void *items, int item_size)
{
        int new_idx;

        new_idx = (int) (num_items * (rand()/(RAND_MAX + 1.0)));

        return items + new_idx * item_size;
}

void *round_robin_selection(int num_items, void *items, int item_size)
{
        static void *current = NULL;
        void *last_on_list;

        last_on_list = items + (num_items - 1) * item_size;

        if (!current || current == last_on_list){
                current = items;
                return current;
        }

        current += item_size;

        return current;
}
