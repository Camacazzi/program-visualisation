#include <iostream>
//#include <Python.h>
//#include <thread>
//#include <chrono>
#include <csignal>
#include <unistd.h>
#include <sys/wait.h>

using namespace std;

int main(){
    //cout<<"Hello World!\5";
    string py = "python2.7 syscount2.py >> output2.txt";
    string prog = "./test";
    pid_t pid = fork();
    int status;
    //start python script

    switch(pid){
        case -1: //error
            perror("fork\n");
            exit(1);

        case 0: //child
            execl(prog.c_str(), 0, 0);
            perror("exec\n");
            exit(1);
        default: //parent
            while(-1 == waitpid(pid, &status, 0));
            cout << "child pid:" << pid << "\n";
            break;
    }
    return 0;
}
