#ifndef SKIPLIST_H_
#define SKIPLIST_H_
#include <iostream>
#include <cstdlib>
#include <cmath>
#include <cstring>
#include "citizen.h"
using namespace std;
#define MAXLEVEL 10

struct SLN { //Skip List Node
    int citizenId, level;
    CN* citizen;    //Ptr to citizen
    SLN** next;     //Array of ptrs
   
    SLN(int level, int citizenId, CN* citizen) {
        this->level = level;
        this->citizenId = citizenId;
        this->citizen = citizen;
        next = new SLN * [level + 1];
        memset(next, 0, sizeof(SLN*) * (level + 1));

    }
    ~SLN() {
        delete[] next;
    }
};


class SkipList {
private:
    SLN* head;
    int level;
    int maxLevel = MAXLEVEL;

public:
    SkipList( CN* citizen) {
        level = 0;
        head =  new SLN(maxLevel, -1, NULL);
    }
    ~SkipList() {  
        SLN* temp = head;
        SLN* next = NULL;

        while (temp != NULL)
        {
            next = temp->next[0];
            delete temp;
            temp = next;
        }
        head = NULL;
    }
  
    void insertCitizen(int citizenId, CN* citizen); //insert citizen at skiplist
    int getRandomLevel();
    int checkIfCitizenExists(int citizenId);    //Search citizen at skip list
    SLN* getHead();
    void deleteCitizen(int citizenId);
    int getPopulationVirus(const string& countryName);    //Get total nodes of a country on a skip list
    int getPopulationAgeGroup(const string& countryName, int minAge, int maxAge); //Get total nodes in the specific age range from country

};

#endif