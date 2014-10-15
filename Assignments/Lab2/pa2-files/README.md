Josh Fermin and Louis Bouddhou
Programmin Assignment 2
DNS Name Resolution Engine

make: command builds the program

make run-multi-lookup: This command does the following - ./multi-lookup input/names*.txt results.txt, this runs the multi-lookup program that contains all the producer and consumer threads for the dns resolver.

make test-multi-lookup: This command does the following - valgrind ./multi-lookup input/names*.txt results.txt, this runs the valgrind tool to test for memory leaks.

make clean: removes any files generated during make.