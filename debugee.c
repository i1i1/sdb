#include <stdio.h>
#include <unistd.h>

#include <sys/types.h>


void __attribute__ ((noinline))
func()
{
    printf("Hello!");
    fflush(stdout);
}

int
main(void)
{
    extern char _start[];

    printf("main %p start %p\n", main, _start);
    fflush(stdout);
    for (int i = 0; i < 4; i++)
        func();
//    printf("[%d] hello, world\n", getpid());
//    fflush(stdout);
//    printf("[%d] current user ID is %d\n", getpid(), getuid());

    return 0;
}

