#include <iostream>
#include "monitorHelp.h"
#include "help.h"

using namespace std;

int signalFlag2=0;

void sighandler(int sig)
{
    if(sig == SIGINT || sig == SIGQUIT){
        cout<<"Monitor received a SIGINT or SIGQUIT.Creating logfile."<<endl;
        signalFlag2 = 11;
    }else if(sig == SIGUSR1){
        cout<<"Monitor received SIGUSR1"<<endl;
        signalFlag2 = 12;
    }else if(sig == SIGUSR2){
        //cout<<"Monitor received SIGUSR2"<<endl;
        signalFlag2 = 13;
    }
    
}

int main(int argc, char *argv[]){

    cout<<"Started monitor with PID "<<getpid()<<endl;
    //cout<<"Arguments:"<<argv[1] <<argv[2] <<"END"<<endl;
    //argv[1]->read
    //argvp[2]->write

    //File descriptors
    int readfd;
    int writefd;
    //Open the read pipe
    if( (readfd = open(argv[1], O_RDWR )) < 0){
        perror("Open child read");
    }

    
    //Open the write pipe
    if( (writefd = open(argv[2], O_RDWR)) < 0){
        perror("Open child write");
    }

    //Signals
    struct sigaction act;
    sigfillset(&act.sa_mask);
    act.sa_flags = 0;
    act.sa_handler = sighandler;

    sigaction(SIGINT, &act, NULL);
    sigaction(SIGQUIT, &act, NULL);
    sigaction(SIGUSR1, &act, NULL);
    sigaction(SIGUSR2, &act, NULL);

    sigset_t myset;
    sigemptyset(&myset);

    int bufferSize, bloomFilterSize, directoriesToRead;

    read(readfd, &bufferSize, sizeof(int));     //Read buffer size
    cout<<"Buffer size is: "<<bufferSize<<endl;

    read(readfd, &bloomFilterSize, sizeof(int));    //Read Bloom Filter Size
    cout<<"Bloom Filter size is: "<<bloomFilterSize<<endl;

    read(readfd, &directoriesToRead, sizeof(int));  //Read Directories
    cout<<"Directories Number: "<<directoriesToRead<<endl;

    /*-----------------Data Structures-----------------------*/
    List* virusList = new List();
	CitizenList* citizenList = new CitizenList();
	CountryList* countryList = new CountryList();
	VirusList* virusNameList = new VirusList();
	AgeList* ageList = new AgeList();
    /*-------------------------------------------------------*/
    Directory *directoryList = new Directory();
    string message;
    for(int i=0; i<directoriesToRead;i++){
        message = readData(readfd, bufferSize, 0);
        cout<<message<<endl;
        directoryList->insertDirectory(message);    //Insert Directory Node to List
        readTxtFiles(directoryList, message, bloomFilterSize, citizenList, countryList, virusNameList, ageList, virusList);  //Insert *.txt files in Directory  (sub)List AND read them  
    }

    /*------------------Debug------------------*/
    //Check the sum of each array cells
    // node *temp = virusList->getHead();
    // int *arr;
    // int sum=0;
    // int j=0;
    // while(temp!=NULL){
    //     cout<<temp->virusName->virus;
    //     if(temp->bloomFilter!=NULL){
    //         arr=temp->bloomFilter->getBloomFilter();
    //         for(j=0;j<bloomFilterSize/4;j++){
    //             sum+=arr[j];
    //         }
    //         cout<<" "<<sum<<endl;
    //     }
    //     sum =0;
    //     temp = temp->next;
    // }
    /*------------------Debug------------------*/
    
    //It's time to send the bloom filter to parent process
    virusList->sendBloomFilter(writefd, bufferSize, bloomFilterSize);    //Send All BloomFilters
    sendData(writefd, bufferSize, "READY"); //Send READY message to parent process
    
    int accepted=0, rejected=0;
    while(1){
        //pause();    //Not sure if it works
        if(signalFlag2==11){    // SIGINT||SIGQUIT
            //Create the log file
            string fileName = "./logs/log_file." + to_string(getpid());
            ofstream MyFile(fileName);
            directoryNode *node = directoryList->getHead();
            while(node!=NULL){
                MyFile<<node->country<<endl;
                node=node->next;
            }
        
            MyFile<<"TOTAL TRAVEL REQUESTS "<<accepted+rejected<<endl;;
            MyFile<<"ACCEPTED "<<accepted<<endl;
            MyFile<<"REJECTED "<<rejected<<endl;
            MyFile.close();
            signalFlag2=0;
        }

        //sigsuspend(&myset);
        if(signalFlag2==12){    //SIGUSR1 - Query 3
            message = readData(readfd, bufferSize, 0);
            cout<<"Finding new files to: "<<message<<endl;
            readTxtFiles(directoryList, message, bloomFilterSize, citizenList, countryList, virusNameList, ageList, virusList); //Read again
            virusList->sendBloomFilter(writefd, bufferSize, bloomFilterSize);    //Send All BloomFilters again
            signalFlag2=0;
        }

        if(signalFlag2==13){    //SIGUSR2 - Queries
            message = readData(readfd, bufferSize, 0);
            string query = message.substr(0,2);
            if(!query.compare("Q1")){   //Query 1
                int citizenId;
                string virusName, travelDate;
                citizenId = stoi(readData(readfd, bufferSize, 0));
                virusName = readData(readfd, bufferSize, 0);
                travelDate = readData(readfd, bufferSize, 0);

                string status, vaccinatedDate;
                status = citizenList->getVaccinationStatus(citizenId, virusName);
                if(!status.compare("YES")){
                    sendData(writefd, bufferSize, "YES");
                    vaccinatedDate = citizenList->getVactinationDate(citizenId, virusName);
                    sendData(writefd, bufferSize, vaccinatedDate);

                    if(stoi(readData(readfd, bufferSize, 0))==1){
                        accepted++;
                    }else{
                        rejected++;
                    }
                }else{
                    sendData(writefd, bufferSize, "NO");
                    rejected++;
                }

            }else if(!query.compare("Q4")){
                int citizenId = stoi(readData(readfd, bufferSize, 0));
                if(!citizenList->checkIfCitizenExists(citizenId)){
                    CN *temp = citizenList->getCitizen(citizenId);
                    message = to_string(temp->citizenId) + "*" + temp->firstName + "*" + temp->lastName + "*" + temp->country->country + "*" + "/" + "*" + "AGE"+ "*" + to_string(temp->age->age) + "*" + "/" + "*";
                    sendData(writefd, bufferSize, message);
                    string record;
                    CI *innerTemp = temp->citizenInfo;
                    while(innerTemp!=NULL){
                        if(!innerTemp->isVactinated.compare("YES")){
                            record = record + innerTemp->virusName->virus + "*" + "VACCINATED ON" + "*" + innerTemp->dateVaccinated + "*" + "/" + "*";
                        }else{
                            record = record + innerTemp->virusName->virus + "*" + "NOT YET VACCINATED" + "*" + "/" + "*";
                        }
                        innerTemp=innerTemp->next;
                    }
                    sendData(writefd, bufferSize, record);
                }else{
                    sendData(writefd, bufferSize, "-1");    //Indicate that monitor couldn't find the citizen
                }
            }
            signalFlag2=0;
        }

    }

    


    delete ageList;
	delete virusNameList;
	delete countryList;
	delete virusList;
	delete citizenList;
    delete directoryList;
     
    return 0;
}