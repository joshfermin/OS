#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h> 

#include "queue.h"
#include "util.h"
#include "multi-lookup.h"

#define MAX_INPUT_FILES 10
#define MAX_RESOLVER_THREADS 10
#define MIN_RESOLVER_THREADS 2
#define MAX_NAME_LENGTH 1025
#define MAX_IP_LENGTH INET6_ADDRSTRLEN
#define MINIMUM_ARGS 2
#define DEBUG 0

bool buffer_finished = false;

pthread_mutex_t buffer_mutex;
pthread_mutex_t output_mutex;

pthread_cond_t empty;
pthread_cond_t full;

// Thread that reads files that have web addresses on it
// and pushes them onto a shared buffer 
void* producer(void* a){

	if (DEBUG) {
		fprintf((stderr), "starting producer thread: \n");
	}

	// opening file 
	// thread_request_arg_t is struct, this gives each thread a filename and the buffer
	thread_request_arg_t* args = (thread_request_arg_t*) a;
	FILE* input_fp = NULL;
	if (DEBUG) { fprintf(stderr, "opening input file: %s\n", args->fname); }
	input_fp = fopen(args->fname, "r");
	if(!input_fp){
		// show error if file cannot be opened
		char errorstr[MAX_NAME_LENGTH];
		sprintf(errorstr, "error opening file %s", args->fname);
		perror(errorstr);
		return NULL;
	}

	// size of what you want to malloc
	char hostname[MAX_NAME_LENGTH];
	while(fscanf(input_fp, "%s", hostname) > 0){ // while you have successfully filled more than 0 items of the argument list
		int hostsize = sizeof(hostname);
		char* hostpointer = malloc(hostsize);
		// One reason to dynamically allocate memory is to effectively use the memory of the computer, 
		// another is to prevent the memory from going out of scope before you are done with it.
		strncpy(hostpointer, hostname, hostsize); // now point to the host name
		
		pthread_mutex_lock(&buffer_mutex);
		// While queue is not full, keep pushing names onto the queue
		// if queue is full condition wait on the full variable
		while((queue_push(args->buffer, hostpointer)) == QUEUE_FAILURE) {
			if (DEBUG) { fprintf(stderr, "queue is full pls hurry\n");}
			pthread_cond_wait(&full, &buffer_mutex);
		}
		pthread_cond_signal(&empty);
		pthread_mutex_unlock(&buffer_mutex);
        if (DEBUG) { fprintf(stderr, "pushing onto queue: %s\n", hostname); }
	}

	// close input file
	fclose(input_fp);

	return NULL; // exit
}

// Thread that takes items off of the buffer from
// what the consumer created and does a DNS lookup on them
void* consumer(void* a)
{
	// gives each thread a shared queue and the shared output file
	thread_resolve_arg_t* args = (thread_resolve_arg_t*) a;

	if (DEBUG) { fprintf(stderr, "Starting consumer thread]n"); }

	while(1) {
		char* hostnamep;
		if (DEBUG) { fprintf(stderr, "grabbing hostname from queue\n"); }
		// if (DEBUG) { fprintf(stderr, "Popping off queue"); }
		pthread_mutex_lock(&buffer_mutex);
		// while queue is not empty, keep popping off from the queue
		// if queue empty (NULL) then do one of two things
		while( (hostnamep = queue_pop(args->rqueue)) == NULL) {
			// if buffer is done being added to, just return
			if (buffer_finished) {
				pthread_mutex_unlock(&buffer_mutex);
				return NULL;
			}
			// if still running, then wait on the empty signal and unlock buffer
			pthread_cond_wait(&empty, &buffer_mutex);
		}
		// when thread is done popping off queue, unlock buffer mutex
		pthread_mutex_unlock(&buffer_mutex);
		// and then signal producer to wake up
		if (DEBUG) { fprintf(stderr, "wakeup producer!\n"); }
		pthread_cond_signal(&full);

		// If queue is not empty, read a name from queue and look it up
		char hostname[MAX_NAME_LENGTH];
		sprintf(hostname, "%s", hostnamep);
		free(hostnamep);

		if (DEBUG) { fprintf(stderr, "dns lookup: %s\n", hostname); }
		char ipstring[INET6_ADDRSTRLEN];
		// Lookup hostname and get IP string (from lookup.c)
	    if(dnslookup(hostname, ipstring, sizeof(ipstring))
	       == UTIL_FAILURE){
		fprintf(stderr, "dnslookup error: %s\n", hostname);
		strncpy(ipstring, "", sizeof(ipstring));
	    } 

	    // When done getting IP string, lock output file mutex,
	    // write to output file, and unlock output file mutex:
	    if (DEBUG) { fprintf(stderr, "resolving hostname: %s\n", hostname); }
	    pthread_mutex_lock(&output_mutex);
	    fprintf(args->outputfp, "%s,%s\n", hostname, ipstring);
	    pthread_mutex_unlock(&output_mutex);
	} 
}

int main(int argc, char* argv[]){
	queue buffer; // shared buffer
	FILE* outputfp = NULL; // shared output file
	pthread_t producer_threads[argc-1];
	pthread_t consumer_threads[MAX_RESOLVER_THREADS];
	int i; // counter
	int buffer_size = QUEUEMAXSIZE; // maxsize for buffer

	// initialize shared buffer
	queue_init(&buffer, buffer_size);

	// Checking for minimum args
	if(argc < MINIMUM_ARGS) {
		fprintf(stderr, "ERROR: Need at least 2 arguments. %d provided. \n", (argc - 1));
		return EXIT_FAILURE;
	}

    // OPEN SHARED OUTPUT FILE:
    outputfp = fopen(argv[(argc-1)], "w"); // create open file pointer with write permissions
    if(!outputfp)
    {
    	perror("ERROR: opening shared output file");
    	return EXIT_FAILURE;
    }

	// checking for max input files
	if(argc > MAX_INPUT_FILES + 1) {
		fprintf(stderr, "ERROR: More than 10 input files provided.");
		return EXIT_FAILURE;
	}

	// CREATE PRODUCER THREADS
	thread_request_arg_t req_args[argc-1]; // length of # of input files
    for(i=1; i<(argc-1); i++){ // until the last file
        req_args[i-1].fname = argv[i]; // get the file name
        req_args[i-1].buffer = &buffer; // add the shared buffer to each thread
        // creating threads for each request 
		int rc = pthread_create(&(producer_threads[i-1]), NULL, producer, &(req_args[i-1])); 
		if (rc){
		    printf("Error making producer thread: %d\n", rc);
		    exit(EXIT_FAILURE);
		}
    }

    // CREATE CONSUMER THREADS
    thread_resolve_arg_t res_args;
    res_args.rqueue = &buffer; // buffer for shared output
    res_args.outputfp = outputfp; // make output file the same for all threads
    for(i=0; i<MAX_RESOLVER_THREADS; i++){
    	int rc = pthread_create(&(consumer_threads[i]), NULL, consumer, &res_args);
    	if (rc){
    		printf("Error making consumer thread: %d\n", rc);
    		exit(EXIT_FAILURE);
    	}
    }

	// WAIT FOR PRODUCER THREADS TO FINISH:
    for(i=0; i<argc-2; i++){
		int rv = pthread_join(producer_threads[i],NULL);
		if (rv) {
			fprintf(stderr, "ERROR: on producer thread join");
		}
    }

    buffer_finished = true;


    // WAIT FOR CONSUMER THREADS TO FINISH:
    for(i=0; i<MAX_RESOLVER_THREADS; i++){
		int rv = pthread_join(consumer_threads[i],NULL);
		if (rv) {
			fprintf(stderr, "ERROR: on consumer thread join");
		}
    }


    // destroy mutexes:
    pthread_mutex_destroy(&buffer_mutex);
    pthread_mutex_destroy(&output_mutex);

    // Take care of mem leaks:
    queue_cleanup(&buffer);
    // close shared output file:
    fclose(outputfp);


    // // destroy condition variables
    // pthread_cond_destroy(&empty);
    // pthread_cond_destroy(&full);

    return EXIT_SUCCESS;
}
