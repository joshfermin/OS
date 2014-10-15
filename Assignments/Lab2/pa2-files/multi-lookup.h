#ifndef MULT_LOOKUP_H
#define MULT_LOOKUP_H

typedef struct {
    char* fname;
    queue* buffer;
} thread_request_arg_t;

typedef struct {
    queue* rqueue;
    FILE* outputfp;
} thread_resolve_arg_t;

void* producer(void*);
void* consumer(void*);

#endif