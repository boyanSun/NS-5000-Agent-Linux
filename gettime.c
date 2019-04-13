#include <stdio.h>
#include <sys/time.h>
#include <stdlib.h>



int main()
{
    float time_use=0;
    struct timeval start;
    struct timeval end;

    gettimeofday(&start,NULL); 
    printf("%d_%06d000\n",start.tv_sec,start.tv_usec);
}


