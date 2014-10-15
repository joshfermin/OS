#include <stdio.h>
#include <unistd.h>

void main(int argc, char** argv)
{
	setreuid(1337,1337);
	char *args[2];
	args[0] = "/bin/sh";
	args[1] = NULL;
	execve(args[0], args, NULL);
}
