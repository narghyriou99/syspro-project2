#ifndef MONITORHELP_H_
#define MONITORHELP_H_

#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <cstring>
#include <cmath>
#include <cstdlib>
#include <ctime>
#include <iomanip>
#include <unistd.h>
#include <sys/wait.h>
#include <dirent.h> //Open and Read Directories
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include "citizen.h"
#include "virus.h"
#include "skiplist.h"
#include "bloomfilter.h"
#include "help.h"

using namespace std;

struct txtFile{
    string name;
    txtFile *next;
    int isRead;
};

struct directoryNode{
    string dirName; //./test/Greece
    string country; //Greece
    int totalTxtFiles;
    txtFile *nextRecord;
    directoryNode* next;
};

class Directory{
    private:
    directoryNode *head, *tail;
    int totalNodes;

    public:
    Directory(){
        head = NULL;
        tail = NULL;
        totalNodes=0;
    }
    ~Directory(){
        directoryNode *temp = head;
        directoryNode *next = NULL;

        while (temp != NULL){
            next = temp->next;
            deleteRecord(temp);
            delete temp;
            temp = next;
        }
    }
    void insertDirectory(const string& path);
    void insertTxtFile(const string& path, const string& fileName);
    void deleteRecord(directoryNode *node);
    directoryNode* getHead();
    int checkIfTxtExist(const string& path, const string& fileName);
};


void readTxtFiles(Directory *directoryList, const string& path, int BloomSize, CitizenList *citList, CountryList *countryList, VirusList* virusNameList, AgeList *ageList, List  *virusList);
int openTxtFile(const string& txtName, int BloomSize, CitizenList *citList, CountryList *countryList, VirusList* virusNameList, AgeList *ageList, List  *virusList);


/*---------------Main----------------*/
void getCommand(List* virusList, CitizenList* citList, CountryList* countryList, VirusList *virusNameList, AgeList *ageList, int BloomSize);
int checkForErrors(int mode, CountryList* countryList, List* virusList, CitizenList* citList, int citizenId, const string& virusName, const string& country);//0 is ok, -1 tis poutanas
string todayDate();

/*-------------Functions-------------*/

void ResetData(int& citizenId, string& firstName, string& lastName, string& country, int& age, string& virusName, string& isVactinated, string& dateVaccinated);
void Entry(CitizenList *citList, CountryList *countryList, VirusList* virusNameList, AgeList *ageList, List  *virusList, int citizenId, const string& firstName, const string& lastName, const string& country, int age, const string& virusName, const string& isVactinated, const string& dateVaccinated, int bfsize);
int checkIfDateisBetween(const string& date1, const string& date2, const string& date3);

/*--------------Queries--------------*/
void vaccineStatusBloom(List* virusList, int citizenId, const string& virusName);	//1st
void vaccineStatus(List* virusList, CN* citizen, const string& virusName);	//2nd 
void vaccineStatusAll(List* virusList, CitizenList* citList, int citizenId); //3rd
void populationStatus(int mode, CountryList* countryList, CitizenList* citList, node* virus, const string& country, const string& date1, const string& date2); //4th
void popStatusByAge(int mode, CitizenList* citList, CountryList* countryList, node* virus, const string& country, const string& date1, const string& date2); //5th
void insertCitizen(CitizenList* citList, CountryList* countryList, VirusList* virusNameList, AgeList* ageList, List* virusList, int citizenId, const string& firstName, const string& lastName, const string& country, int age, const string& virusName, const string& isVactinated, const string& dateVaccinated, int bfsize); //6th
void listNonVaccinatedPersons(node* virus);	//8th

#endif