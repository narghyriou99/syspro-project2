#ifndef CITIZEN_H_
#define CITIZEN_H_
#include <iostream>
#include <cstdlib>
#include <cmath>
#include <cstring>
using namespace std;
/*--------------------Helping-Lists--------------------*/
struct Age {
    int age;
    Age* next;
};

class AgeList {
private:
    Age* head, * tail;
    int totalAges;

public:
    AgeList() {
        totalAges = 0;
        head = NULL;
        tail = NULL;
    }
    ~AgeList() {
        Age* temp = head;
        Age* next = NULL;

        while (temp != NULL)
        {
            next = temp->next;
            delete temp;
            temp = next;
        }
        head = NULL;
        tail = NULL;
    }
    Age* InsertAge(int age);
    Age* checkIfAgeExists(int age);
    Age* getHead();
};


struct Virus {
    string virus;
    Virus* next;
};

class VirusList{
private:
    Virus* head, *tail;
    int totalViruses;
public:
    VirusList() {
        totalViruses = 0;
        head = NULL;
        tail = NULL;
    }
    ~VirusList() {
        Virus* temp = head;
        Virus* next = NULL;

        while (temp != NULL)
        {
            next = temp->next;
            delete temp;
            temp = next;
        }
        head = NULL;
        tail = NULL;
    }
    Virus* InsertVirus(const string& virusName);
    Virus* checkIfVirusExists(const string& virusName);
    int getTotalViruses();
};




struct Country {
    string country;
    int population;
    Country* next;
};

class CountryList {
private:
    Country* head, *tail;
    int totalCountries;
public:
    CountryList() {
        totalCountries = 0;
        head = NULL;
        tail = NULL;
    }
    ~CountryList() {
        Country* temp = head;
        Country* next = NULL;

        while (temp != NULL)
        {
            next = temp->next;
            delete temp;
            temp = next;
        }
        head = NULL;
        tail = NULL;
    }
    Country* InsertCountry(const string& country);
    Country* checkIfCountryExists(const string& country);
    Country* getHead();
};

struct CI {
    Virus* virusName;
    string isVactinated, dateVaccinated;
    CI* next;
    CI(Virus* virusName, const string& isVactinated, const string& dateVaccinated) {
        this->virusName = virusName;
        this->isVactinated = isVactinated;
        this->dateVaccinated = dateVaccinated;
        this->next = NULL;
    }
    /*~CI() {
        CI* temp = next;
        CI* Next = NULL;

        while (temp != NULL)
        {
            Next = temp->next;
            delete temp;
            temp = Next;
        }
    }*/
};

/*-----------------------CitizenList-----------------------*/

struct CN {
    int citizenId;
    string firstName, lastName;
    Age* age;
    Country* country;
    CI* citizenInfo;
    CN* next;
};

class CitizenList {
private:
    CN* head, * tail;
    int totalEntries, vaccinatedCitizens, nonVaccinatedCitizens;
public:
    CitizenList() {
        head = NULL;
        tail = NULL;
        totalEntries = 0;
        vaccinatedCitizens = 0;
        nonVaccinatedCitizens = 0;
    }
    ~CitizenList() {
        CN* temp = head;
        CN* next = NULL;

        while (temp != NULL)
        {
            next = temp->next;
           // delete temp->citizenInfo;
            deleteRecord(temp); //delete inner records
            delete temp;
            temp = next;
        }
        head = NULL;
        tail = NULL;
    }

    void insertCitizen(int mode, int citizenId, const string& firstName, const string& lastName, Country* country, Age* age, Virus* virusName, const string& isVactinated, const string& dateVaccinated);
    int checkIfCitizenVirusExists(int citizenId, const string& virusName);
    string  getVaccinationStatus(int citizenId, const string& virusName);      //Get vaccinate status for a spesific citizen, virus
    void setVactinationStatus(int citizenId, const string& virusName, const string& isVactinated, const string& dateVaccinated);    //Sinithos apo NO se YES
    void printList();
    int checkForInconsistentRecords(int citizenId, const string& firstName, const string& lastName, const string& country, int age, const string& virusName, const string& isVactinated, const string& dateVaccinated); //1->Entry -1->Skip 
    int checkForSameRecords(int citizenId, const string& virusName, const string& isVactinated, const string& dateVaccinated);
    int checkIfCitizenExists(int citizenId);
    CN* getCitizen(int citizenId);
    CI* getRecord(CN* citizen, const string& virusName);
    CN* getHead();
    string getVactinationDate(int citizenId, const string& virusName);
    void deleteRecord(CN* citizen);
    
};

#endif