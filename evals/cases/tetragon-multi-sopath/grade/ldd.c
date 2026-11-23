// Stand-in for ldd, which tetragon runs to find the target's libc.
#include <unistd.h>

int main(int argc, char **argv)
{
	execl("/lib64/ld-linux-x86-64.so.2", "ld.so", "--list", argv[1], (char *)0);
	return 127;
}
