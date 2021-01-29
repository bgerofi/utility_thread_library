#define _GNU_SOURCE
#include <dlfcn.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <sched.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>

//#define HOOK_SYSCALLS
#ifdef HOOK_SYSCALLS
#include <libsyscall_intercept_hook_point.h>
#include <syscall.h>
#endif // HOOK_SYSCALLS

//#define DEBUG_PRINT

#ifdef DEBUG_PRINT
#define	dprintf(...) printf(__VA_ARGS__)
#else
#define dprintf(...) do { if (0) printf(__VA_ARGS__); } while (0)
#endif

#undef pthread_create

typedef int (*__pthread_create_fn)(pthread_t *thread,
		const pthread_attr_t *attr,
		void *(*start_routine) (void *),
		void *arg);

static __pthread_create_fn orig_pthread_create = 0;

char *addr_to_lib(void *addr, unsigned long *offset_in_lib)
{
	char maps_path[PATH_MAX];
	FILE * fp;
	void *start, *end;
	char perms[4];
	unsigned long offset;
	unsigned long dev[2];
	int inode;
	char path[PATH_MAX];

	sprintf(maps_path,"/proc/self/maps");
	fp = fopen(maps_path, "r");
	if (fp == NULL) {
		fprintf(stderr,"error: cannot open the memory maps, %s\n",
				strerror(errno));
		return NULL;
	}

	memset(path, 0, sizeof(path));
	while (fscanf(fp, "%012lx-%012lx %4s %lx %lx:%lx %d%[^\n]",
				(unsigned long *)&start,
				(unsigned long *)&end,
				perms, &offset, &dev[0], &dev[1], &inode, path) != EOF) {

		if (start <= addr && end > addr) {
			fclose(fp);
			if (offset_in_lib)
				*offset_in_lib = (unsigned long)(addr - start);
			return strlen(path) > 0 ?
				strdup(&path[strspn(path, " \t")]) : NULL;
		}

		memset(path, 0, sizeof(path));
	}

	fclose(fp);

	return NULL;
}

struct __uti_arg {
	void *(*start_routine)(void *);
	void *arg;
	int cpu;
};

void *__uti_start_routine(void *arg)
{
	struct __uti_arg *uti_arg = (struct __uti_arg *)arg;

	/* Bind to target CPU if requested */
	if (uti_arg->cpu != -1) {
		cpu_set_t set;

		CPU_ZERO(&set);
		CPU_SET(uti_arg->cpu, &set);

		sched_setaffinity(0, sizeof(set), &set);
	}

	dprintf("%s: @ CPU %d -> 0x%lx\n",
		__func__, sched_getcpu(),
		(unsigned long)uti_arg->start_routine);

	return uti_arg->start_routine(uti_arg->arg);
}

int pthread_create(pthread_t *thread,
		const pthread_attr_t *attr,
		void *(*start_routine) (void *),
		void *arg)
{
	char *lib = NULL;
	int util_thread = 1;
	unsigned long offset = 0;
	int ret;
	struct __uti_arg *uti_arg;

	dprintf("%s: 0x%lx (%s)\n",
			__func__,
			(unsigned long)start_routine,
			getenv("UTI_BIND_CPUS"));

	if (!orig_pthread_create) {
		orig_pthread_create =
			(__pthread_create_fn)dlsym(RTLD_NEXT, "pthread_create");
	}

	lib = addr_to_lib(start_routine, &offset);
	if (lib && (strstr(lib, "iomp") || strstr(lib, "psm"))) {
		util_thread = 0;
	}

	dprintf("%s: 0x%lx is in %s @ 0x%lx %s\n",
			__func__,
			(unsigned long)start_routine,
			lib ? lib : "(unknown)",
			offset,
			util_thread ? "(utility thread)" : "");

	if (lib)
		free(lib);
	
	if (util_thread) {
		uti_arg = malloc(sizeof(*uti_arg));
		if (!uti_arg) {
			goto out;
		}

		uti_arg->start_routine = start_routine;
		uti_arg->arg = arg;
		uti_arg->cpu = -1;

		start_routine = __uti_start_routine;
		arg = uti_arg;

		/* Figure out target CPU based on environment */
		if (getenv("UTI_BIND_CPUS") && getenv("MPI_LOCALRANKID")) {
			char *saveptr;
			char *cpu_string;
			int i;
			int local_rank = atoi(getenv("MPI_LOCALRANKID"));
			char *uti_cpus = strdup(getenv("UTI_BIND_CPUS"));
			if (!uti_cpus) {
				goto out;
			}

			for (i = 0, cpu_string = strtok_r(uti_cpus, ",", &saveptr);
					i < local_rank; ++i) {
				cpu_string = strtok_r(NULL, ",", &saveptr);
			}

			if (cpu_string) {
				/* Override pthread_attr if set */
				if (attr) {
					cpu_set_t set;

					CPU_ZERO(&set);
					CPU_SET(atoi(cpu_string), &set);
					pthread_attr_setaffinity_np(
							(pthread_attr_t *)attr, sizeof(set), &set);
				}

				uti_arg->cpu = atoi(cpu_string);
			}

			free(uti_cpus);
		}
	}

out:
	ret = orig_pthread_create(thread, attr, start_routine, arg);
	return ret;
}

#ifdef HOOK_SYSCALLS
static int hook(long syscall_number,
		long arg0, long arg1,
		long arg2, long arg3,
		long arg4, long arg5,
		long *result)
{
	if (syscall_number == SYS_clone) {
		printf("%s: SYS_clone: 0x%lx\n",
			__func__, arg0);
	}

	return 1;
}


static __attribute__((constructor)) void init(void)
{
	// Set up the callback function
	intercept_hook_point = hook;
}
#endif // HOOK_SYSCALLS
