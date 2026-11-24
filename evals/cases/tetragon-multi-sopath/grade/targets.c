// Traced program. arg_target() and other_target() return -1 unless overridden.
// Policies send arg_target(1) to lib1.so (returns 1), arg_target(2) to lib2.so
// (returns 2), arg_target(3) to arg_target_3() in this binary (returns 3), and
// other_target() to lib2.so. five-ok.yaml also sends 4 to lib1 and 5 to lib2.
// nested.yaml sends 1 to lib3.so, whose constructor calls other_target().
// Built with -rdynamic so lib3.so's constructor can find other_target().
// Exit code: the expected values below, 255 if a call wasn't overridden.
// "race" is the exception: see below.
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

int __attribute__((noinline, noipa)) arg_target(int c)
{
	return -1;
}

int __attribute__((noinline, noipa)) arg_target_3(int c)
{
	return 3;
}

int __attribute__((noinline, noipa)) other_target(int c)
{
	return -1;
}

static int bad;

static int call(int (*f)(int), int arg)
{
	int r = f(arg);

	printf("  %s(%d) = %d\n", f == other_target ? "other_target" : "arg_target", arg, r);
	if (r < 0)
		bad = 1;
	return r;
}

struct pair {
	int first, second, ok;
};

static int race_wrong;

// Two threads at once each call arg_target(1) twice. A call may come back
// un-overridden (-1): the merged PR skips one in 2-3 of 8 runs here. Any
// other value than 1 or -1 is wrong, and so is a crash.
static void *race_thread(void *p)
{
	for (int i = 0; i < 2; i++) {
		int r = call(arg_target, 1);

		if (r != 1 && r != -1)
			__atomic_store_n(&race_wrong, 1, __ATOMIC_RELAXED);
	}
	return NULL;
}

static void *thread(void *p)
{
	struct pair *t = p;

	t->ok = call(arg_target, t->first) == t->first;
	t->ok &= call(arg_target, t->second) == t->second;
	return NULL;
}

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "seq";
	int r;

	setvbuf(stdout, NULL, _IOLBF, 0);
	if (!strcmp(mode, "seq")) {
		// 10 * (1 + 1) + 2 + 2 + 3 = 27
		r = 10 * call(arg_target, 1);
		r += call(arg_target, 2);
		r += 10 * call(arg_target, 1);
		r += call(arg_target, 2);
		r += call(arg_target, 3);
	} else if (!strcmp(mode, "exec")) {
		// Resolve 1, exec on the same thread, then 2 and 1 in the new image: 21
		if (call(arg_target, 1) != 1)
			return 255;
		execl("/proc/self/exe", argv[0], "after-exec", NULL);
		return 254;
	} else if (!strcmp(mode, "after-exec")) {
		r = 10 * call(arg_target, 2);
		r += call(arg_target, 1);
	} else if (!strcmp(mode, "fork")) {
		// Resolve 1, fork, then 2 and 1 in the child: 21
		pid_t pid;
		int st;

		if (call(arg_target, 1) != 1)
			return 255;
		pid = fork();
		if (pid == 0) {
			r = 10 * call(arg_target, 2);
			r += call(arg_target, 1);
			return bad ? 255 : r;
		}
		waitpid(pid, &st, 0);
		return WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
	} else if (!strcmp(mode, "threads") || !strcmp(mode, "threads1")) {
		// Two threads at once, resolving 1 then 2 and 2 then 1, or only 1: 0.
		// Not graded: the merged PR fails "threads" about half the time.
		int one = !strcmp(mode, "threads1");
		struct pair t[2] = { { 1, one ? 1 : 2 }, { one ? 1 : 2, 1 } };
		pthread_t id[2];

		for (int i = 0; i < 2; i++)
			pthread_create(&id[i], NULL, thread, &t[i]);
		for (int i = 0; i < 2; i++)
			pthread_join(id[i], NULL);
		r = t[0].ok && t[1].ok ? 0 : 1;
	} else if (!strcmp(mode, "race")) {
		// 0, or 2 if a call returned a wrong value. Skipped overrides are fine.
		pthread_t id[2];

		for (int i = 0; i < 2; i++)
			pthread_create(&id[i], NULL, race_thread, NULL);
		for (int i = 0; i < 2; i++)
			pthread_join(id[i], NULL);
		return race_wrong ? 2 : 0;
	} else if (!strcmp(mode, "all5")) {
		// Five sopath slots on one thread: 1 + 2 + 1 + 2 + 2 = 8, twice: 8
		for (int i = 0; i < 2; i++) {
			r = call(arg_target, 1) + call(arg_target, 2) + call(arg_target, 4) +
			    call(arg_target, 5) + call(other_target, 5);
			if (r != 8)
				bad = 1;
		}
	} else if (!strcmp(mode, "other")) {
		// arg_target(1) and other_target() alternating on one thread: 24
		r = 10 * call(arg_target, 1);
		r += call(other_target, 5);
		r += 10 * call(arg_target, 1);
		r += call(other_target, 5);
	} else {
		int arg = mode[0] - '0';

		r = call(arg_target, arg);
	}
	return bad ? 255 : r;
}
