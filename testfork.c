 
 
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>

int writing(pid_t pid){
    FILE *file_pointer; 
	
	// open the file "name_of_file.txt" for writing
	file_pointer = fopen("name_of_forkfile.txt", "w"); 
    sleep(1);
 
	// Write to the file
	fprintf(file_pointer, "PID of child is : %d", pid);
    fflush(file_pointer);
	fprintf(file_pointer, "Writing 2 electric boogaloo : %d", pid);
	
	// Close the file
	fclose(file_pointer);
    return 0;
}

int writing_child(){
	sleep(1);
	perror("writing child!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
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
	//sleep(1);
	pid_t pid = fork();
    int status;
	switch(pid){
        case -1: //error
            perror("fork\n");
            exit(1);

        case 0: //child
			for(int i = 0; i < 4; i++)
				writing_child();
            perror("exec\n");
            break;
        default: //parent
			//for(int i = 0; i < 4; i++)
			writing(pid);
            break;
			//waitpid(pid, &status, 0);
    }
    //sleep(2);
	return 0;
}
