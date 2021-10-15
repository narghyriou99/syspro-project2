#include "monitorHelp.h"

using namespace std;

void CitizenList::insertCitizen(int mode, int citizenId, const string& firstName, const string& lastName, Country* country, Age* age, Virus* virusName, const string& isVactinated, const string& dateVaccinated) {
	if (!mode) {
		CN* temp = new CN;
		temp->citizenId = citizenId;
		temp->firstName = firstName;
		temp->lastName = lastName;
		temp->country = country;
		temp->country->population++;
		temp->age = age;
		temp->citizenInfo = new CI(virusName, isVactinated, dateVaccinated);
		temp->next = NULL;
		totalEntries++;
		if (!isVactinated.compare("YES")) {
			vaccinatedCitizens++;
		}
		else {
			nonVaccinatedCitizens++;
		}

		if (head == NULL) {
			head = temp;
			tail = temp;
			temp = NULL;
		}
		else {
			tail->next = temp;
			tail = temp;
		}
	}
	else {	//Add new virus at existing citizen
		CI* info = new CI(virusName, isVactinated, dateVaccinated);
		CN* temp = getCitizen(citizenId);
		info->next = temp->citizenInfo;
		temp->citizenInfo = info;	
		info = NULL;
		temp = NULL;
	}
	
}

int CitizenList::checkIfCitizenVirusExists(int citizenId, const string& virusName){
	if (head == NULL) {
		return -1;	//Skip 
	}
	else {
		CN* temp = head;
		while (temp != NULL) {
			if (temp->citizenId==citizenId) {
				CI* innerTemp = temp->citizenInfo;
				while (innerTemp != NULL) {
					if (!innerTemp->virusName->virus.compare(virusName)) {
						return 0;	//Virus Exists for citizen
					}
					innerTemp = innerTemp->next;
				}	
			}
			temp = temp->next;
		}
	}
	return -1;	//Doesnt exist
}

string CitizenList::getVaccinationStatus(int citizenId, const string& virusName){
	CN* temp = head;
	while (temp != NULL) {
		if (temp->citizenId == citizenId) {
			CI* innerTemp = temp->citizenInfo;
			while (innerTemp != NULL) {
				if (!innerTemp->virusName->virus.compare(virusName)) {
					return innerTemp->isVactinated;	//Return YES or NO
				}
				innerTemp = innerTemp->next;
			}
		}
		temp = temp->next;
	}
	return 0;
}

void CitizenList::setVactinationStatus(int citizenId, const string& virusName, const string& isVactinated, const string& dateVaccinated){
	CN* temp = head;
	while (temp != NULL) {
		if (temp->citizenId == citizenId) {
			CI* innerTemp = temp->citizenInfo;
			while (innerTemp != NULL) {
				if (!innerTemp->virusName->virus.compare(virusName)) {
					innerTemp->isVactinated = isVactinated;
					innerTemp->dateVaccinated = dateVaccinated;
				}
				innerTemp = innerTemp->next;
			}
		}
		temp = temp->next;
	}
}

void CitizenList::printList(){
	CN* temp = head;
	cout << "Vaccinated: " << vaccinatedCitizens << endl;
	cout << "Non-Vaccinated: " << nonVaccinatedCitizens << endl;
	while (temp != NULL) {
		cout << temp->citizenId << " " << temp->firstName << " " << temp->lastName << " " << temp->country->country << " " << temp->age->age << " ";
		CI* innerTemp = temp->citizenInfo;
		while (innerTemp!=NULL) {
			cout << innerTemp->virusName->virus << " " << innerTemp->isVactinated << " " << innerTemp->dateVaccinated <<", ";
			innerTemp = innerTemp->next;
		}
		cout << endl;
		temp = temp->next;
	}
}

int CitizenList::checkForInconsistentRecords(int citizenId, const string& firstName, const string& lastName, const string& country, int age, const string& virusName, const string& isVactinated, const string& dateVaccinated){
	//Various checks
	CN* temp = head;
	while (temp != NULL) {
		if (temp->citizenId == citizenId) {	
			//Elegxos gia ID, an ta firstname, lastname, country, age einai ta idia
			if (temp->firstName.compare(firstName) || temp->lastName.compare(lastName) || temp->age->age != age || temp->country->country.compare(country)) {
				cout << "ERROR IN RECORD " <<citizenId<< endl;
				return -1;
			}
			
			//Check an einai ola idia
			CI* innerTemp = temp->citizenInfo;
			while (innerTemp != NULL) {
				if (!innerTemp->virusName->virus.compare(virusName) && !innerTemp->isVactinated.compare(isVactinated) && !innerTemp->dateVaccinated.compare(dateVaccinated)) {
					cout << "DUBLICATE RECORD FOUND " << citizenId << endl;
					return -1;	
				}
				innerTemp = innerTemp->next;
			}

			//Elegxos gia:Oloidia records, diaforetiko status kai dates
			CI* innerHead = temp->citizenInfo;
			while (innerHead != NULL) {
				if (!innerHead->virusName->virus.compare(virusName)) {
					cout << "ERROR IN RECORD " << citizenId << endl;
					return -1;
				}
				innerHead = innerHead->next;
			}
		}
		temp = temp->next;
	}

	return 1;
}

int CitizenList::checkForSameRecords(int citizenId, const string& virusName, const string& isVactinated, const string& dateVaccinated){
	CN* temp = head;
	while (temp != NULL) {	
		if (temp->citizenId == citizenId){
			CI* innerTemp = temp->citizenInfo;
			while (innerTemp != NULL) {
				if (!innerTemp->virusName->virus.compare(virusName) && !innerTemp->isVactinated.compare(isVactinated) && !innerTemp->dateVaccinated.compare(dateVaccinated)) {
					return 0;	//Same record found
				}
				innerTemp = innerTemp->next;
			}
		}
		temp = temp->next;
	}
	return -1;	//There is no same person
}

int CitizenList::checkIfCitizenExists(int citizenId){
	CN* temp = head;
	while (temp != NULL) {
		if (temp->citizenId == citizenId) {
			return 0;	//Same record found
		}
		temp = temp->next;
	}
	return -1;	//There is no such person
}

CN* CitizenList::getCitizen(int citizenId){
	CN* temp = head;
	while (temp != NULL) {
		if (temp->citizenId == citizenId) {
			return temp;	//Same record found
		}
		temp = temp->next;
	}
	return NULL;	//There is no such person
}

CI* CitizenList::getRecord(CN* citizen, const string& virusName){
	CI* temp = citizen->citizenInfo;
	while (temp != NULL) {
		if (!temp->virusName->virus.compare(virusName)) {
			return temp;
		}
		temp = temp->next;
	}
	return NULL;
}

CN* CitizenList::getHead(){
	return this->head;
}

string CitizenList::getVactinationDate(int citizenId, const string& virusName){
	CN* temp = head;
	string empty;
	while (temp != NULL) {
		if (temp->citizenId == citizenId) {
			CI* innerTemp = temp->citizenInfo;
			while (innerTemp != NULL) {
				if (!innerTemp->virusName->virus.compare(virusName)) {
					if (!innerTemp->isVactinated.compare("YES"))
						return innerTemp->dateVaccinated;	//Return date of vaccination
				}
				innerTemp = innerTemp->next;
			}
		}
		temp = temp->next;
	}
	return empty;
}

void CitizenList::deleteRecord(CN* citizen){
	CI* temp = citizen->citizenInfo;
	CI* next = NULL;

	while (temp != NULL)
	{
		next = temp->next;
		delete temp;
		temp = next;
	}
}



Country* CountryList::InsertCountry(const string& country){
	Country* temp = new Country;
	temp->country = country;
	temp->population = 0;
	temp->next = NULL;
	totalCountries++;
	if (head == NULL) {
		head = temp;
		tail = temp;
	}
	else {
		tail->next = temp;
		tail = temp;
	}

	return temp;
}

Country* CountryList::checkIfCountryExists(const string& country){
	Country* temp = head;
	while (temp != NULL) {
		if (!temp->country.compare(country)) {
			return temp;
		}
		temp = temp->next;
	}
	return NULL;
}

Country* CountryList::getHead(){
	return this->head;
}


Virus* VirusList::InsertVirus(const string& virusName){
	Virus* temp = new Virus;
	temp->virus = virusName;
	temp->next = NULL;
	totalViruses++;
	if (head == NULL) {
		head = temp;
		tail = temp;
	}
	else {
		tail->next = temp;
		tail = temp;
	}

	return temp;
}

Virus* VirusList::checkIfVirusExists(const string& virusName){
	Virus* temp = head;
	while (temp != NULL) {
		if (!temp->virus.compare(virusName)) {
			return temp;
		}
		temp = temp->next;
	}
	return NULL;
}

int VirusList::getTotalViruses(){
	return this->totalViruses;
}

Age* AgeList::InsertAge(int age){
	Age* temp = new Age;
	temp->age = age;
	temp->next = NULL;
	totalAges++;
	if (head == NULL) {
		head = temp;
		tail = temp;
	}
	else {
		tail->next = temp;
		tail = temp;
	}

	return temp;
}

Age* AgeList::checkIfAgeExists(int age){
	Age* temp = head;
	while (temp != NULL) {
		if (temp->age == age) {
			return temp;
		}
		temp = temp->next;
	}
	return NULL;
}

Age* AgeList::getHead(){
	return this->head;
}
