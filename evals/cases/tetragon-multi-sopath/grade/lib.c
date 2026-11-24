// Replacement, built as libN.so with -DVALUE=N. lib2.so gets a 4 KiB pad
// before repl, so repl sits at a different offset in each library and a
// symbol offset used for the wrong library calls into the pad, not repl.
#if VALUE == 2
__attribute__((noinline, used)) int pad(int c)
{
	__asm__ volatile("jmp 1f\n\t.skip 4096, 0xcc\n1:");
	return c;
}
#endif

int repl(int c)
{
	return VALUE;
}
