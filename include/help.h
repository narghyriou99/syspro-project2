#ifndef HELP_H_
#define HELP_H_

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/wait.h>
#include <dirent.h> //Open and Read Directories
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <fstream>


using namespace std;

/*----------------Hash-----------------------*/
unsigned long Newdjb2(string& str);
unsigned long Newsdbm(string& str);
unsigned long Newhash_i(string& str, unsigned int i);
/*--------------------------------------------*/

/*---------------TravelMonitor----------------*/

struct countyInfo{
    string country;
    string path;
    countyInfo *next;
};

class FilePath{
private:
    countyInfo *head;
    int totalCountries;
    int totalPaths;
public:
    FilePath(){
        head=NULL;
        totalCountries=0;
        totalPaths=0;
    }

    ~FilePath(){
        countyInfo* temp = head;
        countyInfo* next = NULL;

        while (temp != NULL){
            next = temp->next;
            delete temp;
            temp = next;
        }
        head = NULL;
    }
    int insertCountryPath(const string& country, const string& path);
    int checkIfCountryExists(const string& country);
    void printList();
    int getTotalSubDirectories();
    string getCountryAtNode(int nodeNumber);
    countyInfo* getHead();

};

struct subDirectory{
    string path;
    subDirectory *next;
};

struct monitorNode{
    int pid;
    int id;
    int totalSubDirectoriesTohandle;
    subDirectory *next_dir;
    monitorNode *next;
};

class MonitorList{
private:
    monitorNode *head, *tail;
    int totalMonitors;
public:
    MonitorList(){
        head=NULL;
        tail=NULL;
        totalMonitors=0;
    }
    ~MonitorList(){
        monitorNode* temp = head;
        monitorNode* next = NULL;

        while (temp != NULL){
            next = temp->next;
            deleteRecord(temp); //Delete inner records
            delete temp;
            temp = next;
        }
        head = NULL;
        tail = NULL;
    }

    void addMonitor(int id);
    void addCountry(int monitor, const string& filepath);
    monitorNode* gethead();
    void print();
    void deleteRecord(monitorNode *monitorNode);
    int getTotalDirectoriesPerMonitor(int monitorNumber);
    string getSpecificDirectory(int monitorNumber, int directoryNumber);
    void insertPid(int monitorNumber, pid_t pid);
    int getMonitor(const string& countryName);  //Given country, it returns the monitor number
};

/*---------------------VirusList---------------------*/
struct request{
    string date;
    string country;
    int status; //1=Accepted, -1=rejected
    request *next;
};

struct virus{
    string virusName;
    int *bloomFilter;
    int size;
    request *record;
    virus *next;
};

class ParentVirusList{
private:
    virus *head, *tail;
    int totalViruses;
    int bfSize;

public:
    ParentVirusList(int BloomSize){
        head=NULL;
        tail=NULL;
        totalViruses=0;
        bfSize = BloomSize;
    }

    ~ParentVirusList(){
        virus* temp = head;
        virus* next = NULL;

        while (temp != NULL){
            next = temp->next;
            if(temp->bloomFilter!=NULL)
                delete[] temp->bloomFilter;
            delete temp;
            temp = next;
        }
        head = NULL;
        tail = NULL;
    }
    void insertVirus(const string& virusName);
    int checkIfVirusExists(const string& virusName);
    void insertBloomFilter(int fd, int bufferSize, const string& virusName);
    virus* getHead();

    int getVaccStatus(int citizenId, const string& virusName);   //1st Query-Check parent's Bloom Filter 
    void insertRequestRecord(const string& virusName, const string& country, const string& date, int status);

};
/*-----------------------------------------------------*/
void showOptions();
void fileDistribution(MonitorList *list, FilePath* filepath, const string& input_dir, int numOfMonitors);

int sendData(int fd, int bufferSize, const string& message);
string readData(int fd, int bufferSize, int messageNo);
int getTotalDirectories(const string& input_dir);
int writeBloomFilter(int fd, int bufferSize, int bloomFilterSize, int *array);
int receiveBloomFilter(int fd, int bufferSize, int bloomFilterSize, int arr[]);
void messageDecryption(string message); //Decrypt and print messages
int reCreateMonitor(pid_t *pid, int *readArray, int *writeArray, pid_t pidDead, int numOfMonitors, int bufferSize, int bloomFilterSize,  MonitorList *monitorList, ParentVirusList *virusList);
int checkIfDateIsMoreThan6Months(const string& dateVaccinated, const string& dateTravel); //Calculate if date Of Vaccination is between [TravelDate - 6months, TravelDate]
int checkIfDateIsBetween(const string& date1, const string& date2, const string& date3);
/*-----------------------Queries-----------------------*/
void travelStats(ParentVirusList *virusList, const string& virusName, const string& date1, const string& date2, const string& country, int mode);

#endif