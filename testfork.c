 
 
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

void writing(pid_t pid){
    FILE *file_pointer; 
	
	// open the file "name_of_file.txt" for writing
	file_pointer = fopen("name_of_forkfile.txt", "w"); 
    sleep(1);
 
	// Write to the file
	fprintf(file_pointer, "PID of child is : %d", pid);
    fflush(file_pointer);
	fprintf(file_pointer, "Writing 2 eletric boogaloo : %d", pid);
	
	// Close the file
	fclose(file_pointer);
    
}

void writing_child(){
    FILE *file_pointer; 
	
	// open the file "name_of_file.txt" for writing
	file_pointer = fopen("name_of_childfile.txt", "w"); 
    sleep(1);
 
	// Write to the file
	fprintf(file_pointer, "I am the child");
	
	// Close the file
	fclose(file_pointer);
    
}

int main(){
	// create a FILE typed pointer
	/*FILE *file_pointer; 
	
	// open the file "name_of_file.txt" for writing
	file_pointer = fopen("name_of_file.txt", "w"); 
    sleep(1);
 
	// Write to the file
	fprintf(file_pointer, "This will write to a file.");
	
	// Close the file
	fclose(file_pointer); */
	//char s[10];
	//scanf("%s", s);
	//sleep(5);
	pid_t pid = fork();
    int status;
	switch(pid){
        case -1: //error
            perror("fork\n");
            exit(1);

        case 0: //child
			writing_child();
            perror("exec\n");
            break;
        default: //parent
			writing(pid);
            break;
    }
    sleep(2);
	return 0;
}
