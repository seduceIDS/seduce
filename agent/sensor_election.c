#include "sensor_election.h"

void *random_election(int num_servers, void *sensors)
{
        int new_idx;

        new_idx = (int) (num_sensors * (rand()/(RAND_MAX + 1.0)));

        return &sensors[new_idx];
}

void *round_robin_election(int num_sensors, void *sensors)
{
        static void *current = NULL;
        void *last_on_list;

        last_on_list = sensors + num_sensors - 1;

        if (!current || current == last_on_list){
                current = &sensors[0];
                return current;
        }

        current++;

        return current;
}
