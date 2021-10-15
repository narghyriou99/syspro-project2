#include <iostream>
#include <string>
#include <sstream>
#include <sys/stat.h>
#include "help.h"

using namespace std;

int signalFlag=0;
int sigChildFlag=0; //1 if parent kills children

pid_t pidDead;

void sighandler(int sig)
{
    if(sig == SIGINT || sig == SIGQUIT){
        cout<<"Parent received a SIGINT or SIGQUIT"<<endl;
        signalFlag = 11;
    }else if(sig == SIGCHLD){
        if(!sigChildFlag){
            cout<<"Parent received a SIGCHLD"<<endl;
            int status;
            pidDead=waitpid(-1, &status, WNOHANG);  //Find the dead process
            //wait(&pidDead);
            signalFlag = 12;
        }else{
            cout<<"Parent received a SIGCHLD.Ignoring that..."<<endl;
        }
    }
}

int main(int argc, char* argv[]){
    if (argc < 9) {
		cout << "Bad option" << endl;
        cout << "Usage: ./travelMonitor –m <numMonitors> -b <bufferSize> -s <sizeOfBloom> -i <input_dir>" << endl;
		return 0;
	}
    int status;
    int sizeOfBloom = 0 , numMonitors = 0, bufferSize = 0, index = 1;
    string input_dir;
	while (index < argc) {
		if (!strcmp(argv[index], "-m"))
			numMonitors = atoi(argv[index + 1]);
		else if (!strcmp(argv[index], "-b"))
			bufferSize = atoi(argv[index + 1]);
        else if (!strcmp(argv[index], "-s"))
			sizeOfBloom = atoi(argv[index + 1]);
        else if (!strcmp(argv[index], "-i"))
			input_dir = argv[index + 1];
		index += 2;
	}

    struct stat buffer;
    if(stat(input_dir.c_str(), &buffer)){   //Check if input_dir exists
        perror(input_dir.c_str());
        return 0;
    }

    if(numMonitors > getTotalDirectories(input_dir)){   //Check if monitors are more than directories
        numMonitors = getTotalDirectories(input_dir);
        cout<<"Adjust monitors to "<<numMonitors<<endl;
    }

    //Signals
    struct sigaction act;
    sigfillset(&act.sa_mask);
    act.sa_flags = 0;
    act.sa_handler = sighandler;

    sigaction(SIGCHLD, &act, NULL);
    sigaction(SIGINT, &act, NULL);
    sigaction(SIGQUIT, &act, NULL);


    MonitorList *monitorList = new MonitorList(); //List of processes
    FilePath *filepath = new FilePath();    //List of countries and subDirectories

    for(int i=0;i<numMonitors;i++){
        monitorList->addMonitor(i); //Add new node -Monitor- to list
    }

    fileDistribution(monitorList, filepath, input_dir, numMonitors);
    //filepath->printList();  //For debugging
    //monitorList->print();

    int *readArray = new int[numMonitors];
    int *writeArray = new int[numMonitors];

    //Named pipes creation
    string pipename;
    for(int i=0;i<numMonitors;i++){
        //1st pipe
        pipename = "fifo" + to_string(i) + to_string(0);
        if(mkfifo(pipename.c_str(), 0700) == -1){
            perror("fifo");
            exit(-1);
        }

        //2nd pipe
        pipename = "fifo" + to_string(i) + to_string(1);
        if(mkfifo(pipename.c_str(), 0700) == -1){
            perror("fifo");
            exit(-1);
        }
    }
    
    //Create Monitors
    pid_t pid[numMonitors];
    string readPipe, writePipe;
    char rp[10], wp[10];

    for(int i = 0; i < numMonitors; i++){
        
        //Open read and write pipes
        pipename = "fifo" + to_string(i) + to_string(0);
        //Open the write pipe
        writeArray[i] = open(pipename.c_str(), O_RDWR);
        if(writeArray[i] < 0){
            perror("Open Parent writer");
        }

        pipename = "fifo" + to_string(i) + to_string(1);
        //Open the read pipe
        readArray[i] = open(pipename.c_str(), O_RDWR);
        if(readArray[i] < 0){
            perror("Open Parent reader");
        }

        //create a process
        pid[i] = fork();
        monitorList ->insertPid(i, pid[i]);
        if(pid[i] == -1){   //Error
            perror("fork");
            exit(-1);
        }else if(pid[i] == 0){  //Child
            //Fix args
            memset(rp, '\0', sizeof(char)*10);
            memset(wp, '\0', sizeof(char)*10);

            readPipe = "fifo" + to_string(i) + to_string(0);
            writePipe = "fifo" + to_string(i) + to_string(1);
            strcpy(rp, readPipe.c_str());
            strcpy(wp, writePipe.c_str());

            char *args[]={(char*)"./monitor", rp, wp, NULL};
            if(execv(args[0], args) == -1){
                perror("Monitor");
                exit(-1);
            }
        }
    }

    int totalDirToSend, totalViruses, BFexists;
    string path, message;
    ParentVirusList *virusList = new ParentVirusList(sizeOfBloom);

    for(int i=0;i<numMonitors;i++){
        write(writeArray[i], &bufferSize, sizeof(int));     //Send Buffer size
        write(writeArray[i], &sizeOfBloom, sizeof(int));    //Send Size of Bloom Filter

        //Send directories
        totalDirToSend = monitorList->getTotalDirectoriesPerMonitor(i);
        write(writeArray[i], &totalDirToSend, sizeof(int));
        for(int j=0;j<totalDirToSend;j++){
            path = monitorList->getSpecificDirectory(i, j);
            sendData(writeArray[i], bufferSize, path);
        }

        //Get total viruses per monitor
        read(readArray[i], &totalViruses, sizeof(int)); 
        for(int j=0;j<totalViruses;j++){
            message = readData(readArray[i], bufferSize, 0);
            cout<<"Message:"<<message;
            if(!virusList->checkIfVirusExists(message))
                virusList->insertVirus(message);
            read(readArray[i], &BFexists, sizeof(int));
            if(BFexists==1){    //Reading Bloom Filter
                cout<<" Bloom Filter Exists"<<endl;
                virusList->insertBloomFilter(readArray[i], bufferSize, message);
            }else{
                cout<<" Bloom Filter does not exist"<<endl;           //Go to next virus
            }
        }
        cout<<"Total Viruses "<<totalViruses<<endl;

        if(!readData(readArray[i], bufferSize, 0).compare("READY")){
            cout<<"Monitor "<<i<<" is ready!"<<endl;
        }

        //usleep(800);
    }

    /*------------------Debug------------------*/
    //Check the sum of each array cells
    // virus *temp = virusList->getHead();
    // int *arr;
    // int sum=0;
    // int j=0;
    // while(temp!=NULL){
    //     cout<<temp->virusName;
    //     arr=temp->bloomFilter;
    //     if(arr!=NULL){ 
    //         for(j=0;j<sizeOfBloom/4;j++){
    //             sum+=arr[j];
    //         }
    //         cout<<" "<<sum<<endl;
    //     }
    //     sum =0;
    //     temp = temp->next;
    // }
    /*------------------Debug------------------*/
    
    int accepted=0, rejected=0;
    string fullCommand, word;
    while(1){
        if(signalFlag==12){ //SIGCHLD
            cout<<"Re-creating monitor..."<<endl;
            reCreateMonitor(pid, readArray, writeArray, pidDead, numMonitors, bufferSize, sizeOfBloom, monitorList, virusList);
            usleep(800);
            signalFlag=0;
        }

        showOptions();
        cin.clear();
        getline(cin, fullCommand);
		istringstream iss(fullCommand);

        if(signalFlag==11){ //SIGINT-SIGQUIT
            signalFlag=0;
            break;
        }
        
        if (fullCommand.substr(0, fullCommand.find(" ")) == "/exit") {
            break;
			
		}else if(fullCommand.substr(0, fullCommand.find(" ")) == "/travelRequest"){
            int citizenId, counter=0;
            string date, countryFrom, countryTo, virusName;
            while (iss >> word) {
					if (counter == 1)
						citizenId = stoi(word);
					if (counter == 2)
						date = word;
                    if (counter == 3)
						countryFrom = word;
                    if (counter == 4)
						countryTo = word;
                    if (counter == 5)
						virusName = word;
					counter++;
			}
            if(counter==6){ //Check if all the arguments have been given
                if(virusList->checkIfVirusExists(virusName)==-1 && !filepath->checkIfCountryExists(countryFrom)){   //Check if the virus and the country exis
                    if(virusList->getVaccStatus(citizenId, virusName)==-1){ //Search Bloom Filter
                        cout<<"REQUEST REJECTED - YOU ARE NOT VACCINATED"<<endl;
                        rejected++;
                        virusList->insertRequestRecord(virusName, countryFrom, date, -1);
                    }else{
                        cout<<"I have to search the monitors"<<endl;
                        int monitor=monitorList->getMonitor(countryFrom);   //Get thew right monitor
                        kill(pid[monitor], SIGUSR2);
                        sendData(writeArray[monitor], bufferSize, "Q1");
                        sendData(writeArray[monitor], bufferSize, to_string(citizenId)); //Send citizenId
                        sendData(writeArray[monitor], bufferSize, virusName);   //Send virus Name
                        sendData(writeArray[monitor], bufferSize, date);    //Send Travel Date

                        //Response
                        message = readData(readArray[monitor], bufferSize, 0);
                        if(!message.compare("YES")){
                            string dateVaccinated = readData(readArray[monitor], bufferSize, 0);
                            int requestStatus;
                            if(checkIfDateIsMoreThan6Months(dateVaccinated, date)==1){  //Check the dates
                                cout<<"REQUEST ACCEPTED - HAPPY TRAVELS"<<endl;
                                accepted++;
                                requestStatus=1;
                                virusList->insertRequestRecord(virusName, countryFrom, date, 1);
                            }else{
                                cout<<"REQUEST REJECTED - YOU WILL NEED ANOTHER VACCINATION BEFORE TRAVEL DATE"<<endl;
                                rejected++;
                                requestStatus=-1;
                                virusList->insertRequestRecord(virusName, countryFrom, date, -1);
                            }
                            sendData(writeArray[monitor], bufferSize, to_string(requestStatus));
                        }else{
                            rejected++;
                        }
                    }
                    usleep(800);
                }else{
                    cout<<"Virus or CountryTo do not exist!"<<endl;
                }

            }else{
                cout<<"Missing arguments!"<<endl;
            }
        }else if(fullCommand.substr(0, fullCommand.find(" ")) == "/travelStats"){
            int counter=0;
            string virusName, date1, date2, country;
            while (iss >> word) {
					if (counter == 1)
						virusName = word;
					if (counter == 2)
						date1 = word;
                    if (counter == 3)
						date2 = word;
                    if (counter == 4)
						country = word;
					counter++;
			}
            if(counter==5){ //For specific country
                travelStats(virusList, virusName, date1, date2, country, 0);
            }else if(counter==4){   //All countries
                travelStats(virusList, virusName, date1, date2, country, 1);
            }else{
                cout<<"Missing arguments!"<<endl;
            }
        }else if(fullCommand.substr(0, fullCommand.find(" ")) == "/addVaccinationRecords"){
            int counter=0;
            string word, country;
            while (iss >> word) {
                if (counter == 1)
					country = word;
				counter++;
            }
            
            if(!filepath->checkIfCountryExists(country)){
                //Send SIGUSR1 to monitor
                int monitor = monitorList->getMonitor(country);
                kill(pid[monitor], SIGUSR1);
                message = input_dir + "/" + country;
                sendData(writeArray[monitor], bufferSize, message); //Send input_dir/Country

                //Receive BloomFilters
                read(readArray[monitor], &totalViruses, sizeof(int)); //Get total viruses per monitor
                for(int j=0;j<totalViruses;j++){
                    message = readData(readArray[monitor], bufferSize, 0);
                    cout<<"Message:"<<message;
                    if(!virusList->checkIfVirusExists(message))
                        virusList->insertVirus(message);
                    read(readArray[monitor], &BFexists, sizeof(int));
                    if(BFexists==1){    //Reading Bloom Filter
                        cout<<" Bloom Filter Exists"<<endl;
                        virusList->insertBloomFilter(readArray[monitor], bufferSize, message);
                    }else{
                        cout<<" Bloom Filter does not exist"<<endl;           //Go to next virus
                    }
                    cout<<"Total Viruses "<<totalViruses<<endl;
                }
            }else{
                cout<<"Country doesn't exist!"<<endl;
            }
        }else if(fullCommand.substr(0, fullCommand.find(" ")) == "/searchVaccinationStatus"){
            int counter=0;
            string citizenId;
            while (iss >> word) {
                if (counter == 1)
					citizenId = word;
				counter++;
            }

            int flag=0;
            for(int i=0;i<numMonitors;i++){ //Sending Signal
                kill(pid[i], SIGUSR2);
                sendData(writeArray[i], bufferSize, "Q4");
                sendData(writeArray[i], bufferSize, citizenId);

                message = readData(readArray[i], bufferSize, 0);
                if(message.compare("-1")){
                    messageDecryption(message);
                    messageDecryption(readData(readArray[i], bufferSize, 0));
                    flag=1;
                }
            }

            if(!flag)
                cout<<"Sorry! I can not find the specific citizen in any monitor"<<endl;
            usleep(800);

        }else{
            cout << "Wrong option. Please re-type your command." << endl;
        }

    }

    sigChildFlag=1;
    //Send SIGKILL to children
    int returnedPid=0;
    for (int i = 0; i < numMonitors; i+=1){
        kill(pid[i], SIGKILL);

        //Wait for all the children to finish
        returnedPid = wait(&status);
		if (returnedPid < 0){
			perror("Wait");
        }
        
        //Close fifos
        close(readArray[i]);
        close(writeArray[i]);

        //Delete fifo files
        readPipe = "fifo" + to_string(i) + to_string(0);
        writePipe = "fifo" + to_string(i) + to_string(1);
        unlink(readPipe.c_str());
        unlink(writePipe.c_str());
    }

    //Create the log file
    string fileName = "./logs/log_file." + to_string(getpid());
    ofstream MyFile(fileName);
    countyInfo *node = filepath->getHead();
    while(node!=NULL){
        MyFile<<node->country<<endl;
        node=node->next;
    }
    
    MyFile<<"TOTAL TRAVEL REQUESTS "<<accepted+rejected<<endl;;
    MyFile<<"ACCEPTED "<<accepted<<endl;
    MyFile<<"REJECTED "<<rejected<<endl;
    MyFile.close();
    
    //Memory release
    delete[] readArray;
    delete[] writeArray;
    delete filepath;
    delete monitorList;
    delete virusList;

    return 0;
}
