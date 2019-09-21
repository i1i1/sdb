#include <stdio.h>
#include <unistd.h>

#include <sys/types.h>

int
main(void)
{
	printf("[%d] hello, world\n", getpid());
	fflush(stdout);
	printf("[%d] current user ID is %d\n", getpid(), getuid());

	return 0;
}

