#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>
#include <sys/wait.h>

int syscall_pebs_start = 463;
int syscall_pebs_end = 464;



long pebs_start(pid_t pid)
{
    return syscall(syscall_pebs_start, pid);
}

long pebs_end(pid_t pid)
{
    return syscall(syscall_pebs_end, pid);
}


int main (int argc, char *argv[])
{
    pid_t pid = fork();

    // if argument is start, call pebs_start
    if (argc == 2 && strcmp(argv[1], "start") == 0) {
        pebs_start(pid);
    }
    // if argument is end, call pebs_end
    else if (argc == 2 && strcmp(argv[1], "end") == 0) {
        pebs_end(pid);
    }
}