 
#include <stdio.h>
#include <unistd.h>

void writing(){
    FILE *file_pointer; 
	
	// open the file "name_of_file.txt" for writing
	file_pointer = fopen("name_of_file.txt", "w"); 
    sleep(1);
 
	// Write to the file
	fprintf(file_pointer, "This will write to a file.");
	
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
    writing();
    sleep(2);
	return 0;
}


