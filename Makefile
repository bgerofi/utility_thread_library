all:  libuti.so

libuti.so: libuti.c
	gcc -Wall -Werror -lpthread -fpic -shared -o libuti.so libuti.c

libuti-hook.so: libuti.c
	gcc -DHOOK_SYSCALLS -I${HOME}/install/syscall_intercept/include/ -L${HOME}/install/syscall_intercept/lib64 -Wl,-rpath=${HOME}/install/syscall_intercept/lib64/ -lsyscall_intercept -Wall -Werror -fpic -shared -o libuti-hook.so libuti.c

clean:
	rm -f libuti*.so

.PONY:
	all
