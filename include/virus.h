#ifndef VIRUS_H_
#define VIRUS_H_
#include <iostream>
#include <cstdlib>
#include <cmath>
#include <cstring>
#include "skiplist.h"
#include "bloomfilter.h"
using namespace std;


struct node {
    Virus* virusName;
    SkipList* VaccinatedSkipList, * NonVaccinatedSkipList;
    BloomFilter* bloomFilter;
    node* next;
    
};

class List {
private:
    node* head, * tail;
    int sumOfNodes;
public:
    List() {
        head = NULL;
        tail = NULL;
        sumOfNodes = 0;
    }
    ~List() {
        deleteSkipLists();  //Delete all skip lists
        node* temp = head;
        node* next = NULL;

        while (temp != NULL)
        {
            next = temp->next;
            if (temp->bloomFilter != NULL)
                delete temp->bloomFilter;
            delete temp;
            temp = next;
        }
        head = NULL;
        tail = NULL;
    }
    void InsertVirus(Virus* virusName); //Insert virus to virusList
    int checkIfVirusExists(const string& virusName);
    void printList();
    void setVaccinatedSkipList(const string& virusName, CN* citizen);   //Create vacc skip list
    void setNonVaccinatedSkipList(const string& virusName, CN* citizen);    //Create non vacc skip list
    SkipList* getVaccinatedSkipList(const string& virusName);   //Get YES skip list for virus Name
    SkipList* getNonVaccinatedSkipList(const string& virusName); //Get NO skip list for virus Name
    BloomFilter* getBloomFilter(const string& virusName);   //Get bloom filter
    void createBloomFilter(const string& virusName, int bfSize);   //Create bloom filter
    void deleteSkipLists();
    node* getHead();
    node* getVirus(const string& virusName);
    /*--------------------------Syspro-2--------------------------*/
    void sendBloomFilter(int fd, int bufferSize, int bloomFilterSize);
};


#endif