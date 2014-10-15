#include <unistd.h>
 
 int main(void)
 {
         while(1)
                 fork();
 }

 // gcc -o assignment1 assignment1.c