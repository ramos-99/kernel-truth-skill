// Like lib.c (repl returns 1), but its constructor calls other_target(), a
// traced symbol with its own sopath override, while lib3.so is being dlopen()ed.
#define _GNU_SOURCE
#include <dlfcn.h>

__attribute__((constructor)) static void init(void)
{
	int (*f)(int) = (int (*)(int))dlsym(RTLD_DEFAULT, "other_target");

	if (f)
		f(5);
}

int repl(int c)
{
	return 1;
}
