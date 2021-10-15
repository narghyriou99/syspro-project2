#include "monitorHelp.h"

using namespace std;

void Directory::insertDirectory(const string& path){
	directoryNode *temp = new directoryNode();
	temp->dirName = path;
	string tempCountry = temp->dirName.substr(temp->dirName.find("/") + 1);
	temp->country =	tempCountry.substr(tempCountry.find("/") + 1);
	temp->nextRecord = NULL;
	temp->totalTxtFiles	= 0;
	temp->next=NULL;
	totalNodes++;

	if(head==NULL){
		head = temp;
		tail = temp;
		temp = NULL;
	}else{
		tail->next = temp;
		tail = temp;
	}
}

void Directory::insertTxtFile(const string& path, const string& fileName){
	directoryNode *temp = head;
	while(temp!=NULL){
		if(!temp->dirName.compare(path)){	//Find correct Directory
			txtFile *file = new txtFile;
			file->name = fileName;
			file->isRead=0;
			file->next = NULL;
			temp->totalTxtFiles++;
			if(temp->nextRecord==NULL){
				temp->nextRecord = file;
			}else{
				txtFile *last = temp->nextRecord;
				while(last->next!=NULL)
					last=last->next;
				last->next = file;
			}
			return;
		}
		temp=temp->next;
	}
}

void Directory::deleteRecord(directoryNode *node){
	txtFile *temp = node->nextRecord;
	txtFile *next = NULL;

	while (temp != NULL)
	{
		next = temp->next;
		delete temp;
		temp = next;
	}
}

directoryNode* Directory::getHead(){
	return this->head;
}

int Directory::checkIfTxtExist(const string& path, const string& fileName){
	directoryNode *temp=head;
	while(temp!=NULL){
		if(!temp->dirName.compare(path)){
			txtFile *innerTemp = temp->nextRecord;
			while(innerTemp!=NULL){
				if(!innerTemp->name.compare(fileName)){
					return -1;	//Found
				}
				innerTemp=innerTemp->next;
			}

		}
		temp=temp->next;
	}
	return 0;	//Didnt find that
}

void readTxtFiles(Directory *directoryList, const string& path, int BloomSize, CitizenList *citList, CountryList *countryList, VirusList* virusNameList, AgeList *ageList, List  *virusList){
    //string paths = "#"; // #./test/CountryA/Country-1.txt#./test/CountryA/Country-1.txt#
    string fileName;
	string fullName;
	struct dirent *dir;
    DIR *dp = opendir(path.c_str());
    if(dp){
        //string unique_path;
        while((dir=readdir(dp)) != NULL){
            if(!strcmp(dir->d_name, ".") || !strcmp(dir->d_name, "..")) //Reject . and ..
                continue;
            if(strstr(dir->d_name, ".txt")){
				fileName = dir->d_name;
				if(!directoryList->checkIfTxtExist(path, fileName)){
					directoryList->insertTxtFile(path, fileName);
					fullName = path + "/" + fileName;
					cout<<"Read from: "<<fullName<<endl;
					openTxtFile(fullName, BloomSize, citList, countryList, virusNameList, ageList, virusList);
				}
            }
        }
		citList->printList();
		virusList->printList();
        closedir(dp);
    }
}

int openTxtFile(const string& txtName, int BloomSize, CitizenList *citList, CountryList *countryList, VirusList* virusNameList, AgeList *ageList, List  *virusList){

	string word;
	int totalRecords = 0;	//All records 
	int count = 1;
	fstream file;
	file.open(txtName);
	if (file.fail()) {
		cout << "Error opening file!" << endl;
		return -1;
	}

	int citizenId, age;
	string firstName, lastName, country, virusName, dateVaccinated, isVaccinated;
	string emptyString;
	emptyString.clear();
	
	while (file >> word){
		switch (count) {
		case 1:
			citizenId = stoi(word);
			break;
		case 2:
			firstName = word;
			totalRecords++;
			break;
		case 3:
			lastName = word;
			break;
		case 4:
			country = word;
			break;
		case 5:
			age = stoi(word);
			break;
		case 6:
			virusName = word;
			break;
		case 7:
			isVaccinated = word;
			break;
		case 8:
			dateVaccinated = word;
			break;
		}
		
		if (count == 8) {
			if (!isVaccinated.compare("YES") && dateVaccinated.length() > 4) {	//Yes with date
				Entry(citList, countryList, virusNameList, ageList, virusList, citizenId, firstName, lastName, country, age, virusName, isVaccinated, dateVaccinated, BloomSize);
				ResetData(citizenId, firstName, lastName, country, age, virusName, isVaccinated, dateVaccinated);
				count = 0;
			}
			if (!isVaccinated.compare("YES") && dateVaccinated.length() <= 4) {	//Yes with no date
				cout << "ERROR IN RECORD " << citizenId << endl;
				ResetData(citizenId, firstName, lastName, country, age, virusName, isVaccinated, dateVaccinated);
				citizenId = stoi(word);
				count = 1;
			}
			if (!isVaccinated.compare("NO") && dateVaccinated.length() > 4) {	// No with date
				cout << "ERROR IN RECORD " << citizenId << endl;
				ResetData(citizenId, firstName, lastName, country, age, virusName, isVaccinated, dateVaccinated);
				count = 0;
			}
			if (!isVaccinated.compare("NO") && dateVaccinated.length() <= 4) {	// No with no date
				Entry(citList, countryList, virusNameList, ageList, virusList, citizenId, firstName, lastName, country, age, virusName, isVaccinated, emptyString, BloomSize);
				ResetData(citizenId, firstName, lastName, country, age, virusName, isVaccinated, dateVaccinated);
				citizenId = stoi(word);
				count = 1;
			}
		}
		count++;
	}
	//Check last record
	if (!isVaccinated.compare("YES") && dateVaccinated.length() > 4) {	//Yes with date
		Entry(citList, countryList, virusNameList, ageList, virusList, citizenId, firstName, lastName, country, age, virusName, isVaccinated, dateVaccinated, BloomSize);
		ResetData(citizenId, firstName, lastName, country, age, virusName, isVaccinated, dateVaccinated);
	}
	if (!isVaccinated.compare("YES") && dateVaccinated.length() <= 4) {	//Yes with no date
		cout << "ERROR IN RECORD " << citizenId << endl;
		ResetData(citizenId, firstName, lastName, country, age, virusName, isVaccinated, dateVaccinated);
	}
	if (!isVaccinated.compare("NO") && dateVaccinated.length() > 4) {	// No with date
		cout << "ERROR IN RECORD " << citizenId << endl;
		ResetData(citizenId, firstName, lastName, country, age, virusName, isVaccinated, dateVaccinated);
	}
	if (!isVaccinated.compare("NO") && dateVaccinated.length() <= 4) {	// No with no date
		Entry(citList, countryList, virusNameList, ageList, virusList, citizenId, firstName, lastName, country, age, virusName, isVaccinated, emptyString, BloomSize);
		ResetData(citizenId, firstName, lastName, country, age, virusName, isVaccinated, dateVaccinated);
	}

	file.close();
	return 0;

}

void getCommand(List* virusList, CitizenList* citList, CountryList* countryList, VirusList* virusNameList, AgeList* ageList, int BloomSize){
	string fullCommand;
	int flag = 0;
	while (!flag) {
		//showOptions();
		getline(cin, fullCommand);
		istringstream iss(fullCommand);
		string word, empty;
		if (fullCommand.substr(0, fullCommand.find(" ")) == "/exit") {
			flag = -1;
		}
		else if (fullCommand.substr(0, fullCommand.find(" ")) == "/vaccineStatusBloom") {
			int counter = 0;
			int citizenId;
			string virusName;
			while (iss >> word) {
				if (counter == 1)
					citizenId = stoi(word);
				if (counter == 2)
					virusName = word;
				counter++;
			}
			if(!checkForErrors(1, countryList, virusList, citList, citizenId,  virusName, empty))	//Check for errors
				vaccineStatusBloom(virusList, citizenId, virusName);
		}
		else if(fullCommand.substr(0, fullCommand.find(" ")) == "/vaccineStatus"){
			if (fullCommand.length() > 19) {
				int counter = 0;
				int citizenId;
				string virusName;
				while (iss >> word) {
					if (counter == 1)
						citizenId = stoi(word);
					if (counter == 2)
						virusName = word;
					counter++;
				}
				if (!checkForErrors(2, countryList, virusList, citList, citizenId, virusName, empty)) 	//Check for errors
					vaccineStatus(virusList, citList->getCitizen(citizenId), virusName);
			}
			else {
				int counter = 0;
				int citizenId;
				string virusName;
				while (iss >> word) {
					if (counter == 1)
						citizenId = stoi(word);
					counter++;
				}
				if (!checkForErrors(3, countryList, virusList, citList, citizenId, virusName, empty))	//Check for errors
					vaccineStatusAll(virusList, citList, citizenId);
			}
			
		}
		else if (fullCommand.substr(0, fullCommand.find(" ")) == "/populationStatus") {
			int args = 1;
			string virusName, country, date1, date2;
			string arg1, arg2, arg3, arg4;
			while (iss >> word) {
				if (args == 2)
					arg1 = word;
				if (args == 3)
					arg2 = word;
				if (args == 4)
					arg3 = word;
				if (args == 5)
					arg4 = word;
				args++;
			}
			args--;
			if (args == 2) {	//Only virusName
				virusName = arg1;
				node* virus = virusList->getVirus(virusName);
				if (!checkForErrors(4, countryList, virusList, citList, 0, virusName, country))	//Check for errors
					populationStatus(0, countryList, citList, virus, country, "1-1-0001", "1-1-9999");
			}
			if (args == 3) {	//Country and VirusName
				country = arg1;
				virusName = arg2;
				node* virus = virusList->getVirus(virusName);
				if (!checkForErrors(4, countryList, virusList, citList, 0, virusName, country))	//Check for errors
					populationStatus(1, countryList, citList, virus, country, "1-1-0001", "1-1-9999");

			}
			if (args == 4) {
				//Check an yparxei paula
				if (arg2.find("-")<arg2.length() && arg3.find("-")<arg3.length()) {
					virusName = arg1;
					date1 = arg2;
					date2 = arg3;
					node* virus = virusList->getVirus(virusName);
					if (!checkForErrors(4, countryList, virusList, citList, 0, virusName, country))	//Check for errors
						populationStatus(0, countryList, citList, virus, country, date1, date2);
				}
				else {
					cout << "ERROR" << endl;
				}
			}
			if (args == 5) {
				country = arg1;
				virusName = arg2;
				date1 = arg3;
				date2 = arg4;
				node* virus = virusList->getVirus(virusName);
				if (!checkForErrors(4, countryList, virusList, citList, 0, virusName, country))	//Check for errors
					populationStatus(1, countryList, citList, virus, country, date1, date2);
			}
		}
		else if (fullCommand.substr(0, fullCommand.find(" ")) == "/popStatusByAge") {
			int args = 1;
			string arg1, arg2, arg3, arg4;
			string virusName, country, date1, date2;
			while (iss >> word) {
				if (args == 2)
					arg1 = word;
				if (args == 3)
					arg2 = word;
				if (args == 4)
					arg3 = word;
				if (args == 5)
					arg4 = word;
				args++;
			}
			args--;
			if (args == 2) {	//Only virusName
				virusName = arg1;
				node* virus = virusList->getVirus(virusName);
				if (!checkForErrors(5, countryList, virusList, citList, 0, virusName, country))	//Check for errors
					popStatusByAge(0, citList, countryList, virus, country, "1-1-0001", "1-1-9999");
			}
			if (args == 3) {	//Country and VirusName
				country = arg1;
				virusName = arg2;
				node* virus = virusList->getVirus(virusName);
				if (!checkForErrors(5, countryList, virusList, citList, 0, virusName, country))	//Check for errors
					popStatusByAge(1, citList, countryList, virus, country, "1-1-0001", "1-1-9999");
			}

			if (args == 4) {
				//Check an yparxei paula
				if (arg2.find("-") < arg2.length() && arg3.find("-") < arg3.length()) {
					virusName = arg1;
					date1 = arg2;
					date2 = arg3;
					node* virus = virusList->getVirus(virusName);
					if (!checkForErrors(5, countryList, virusList, citList, 0, virusName, country))	//Check for errors
						popStatusByAge(0, citList, countryList, virus, country, date1, date2);
				}
				else {
					cout << "ERROR" << endl;
				}
			}
			if (args == 5) {
				country = arg1;
				virusName = arg2;
				date1 = arg3;
				date2 = arg4;
				node* virus = virusList->getVirus(virusName);
				if (!checkForErrors(5, countryList, virusList, citList, 0, virusName, country))	//Check for errors
					popStatusByAge(1, citList, countryList, virus, country, date1, date2);

			}
		}
		else if (fullCommand.substr(0, fullCommand.find(" ")) == "/insertCitizenRecord") {
			int i = 0;
			int citizenId, age;
			string word, firstName, lastName, country, virusName, isVaccinated, dateVaccinated;
			while (iss >> word) {
				switch (i) {
				case 1:
					citizenId = stoi(word);
					break;
				case 2:
					firstName = word;
					break;
				case 3:
					lastName = word;
					break;
				case 4:
					country = word;
					break;
				case 5:
					age = stoi(word);
					break;
				case 6:
					virusName = word;
					break;
				case 7:
					isVaccinated = word;
					break;
				case 8:
					dateVaccinated = word;
					break;
				}
				i++;
			}
			/*Check for entry error 
			* An vrw to idio id, kanw entry
			*	An vrw idio virus:
			*			An exw eggrafi me yes: An vrw YES, ektipono minima, An vrw no, kanw update rcords, skip list, bloom
			*			An exw eggrafi me no: An exw YES kano tin allagi apo NO se YES, alliws vgazw error
			*	An vrw diaforetiko virus:Entry
			*/
			if (!isVaccinated.compare("YES") && dateVaccinated.length() > 4) {	//Yes with date
				insertCitizen(citList, countryList, virusNameList, ageList, virusList, citizenId, firstName, lastName, country, age, virusName, isVaccinated, dateVaccinated, BloomSize);
			}
			if (!isVaccinated.compare("YES") && dateVaccinated.length() == 0) {	// Yes with no date
				cout << "ERROR IN RECORD " << citizenId << endl;
				continue;
			}
			if (!isVaccinated.compare("NO") && dateVaccinated.length() > 4) {	// No with date
				cout << "ERROR IN RECORD " << citizenId << endl;
				continue;
			}
			if (!isVaccinated.compare("NO") && dateVaccinated.length() == 0) {	// No
				insertCitizen(citList, countryList, virusNameList, ageList, virusList, citizenId, firstName, lastName, country, age, virusName, isVaccinated, dateVaccinated, BloomSize);
			}

		}
		else if (fullCommand.substr(0, fullCommand.find(" ")) == "/vaccinateNow") {
			int i = 0;
			int citizenId, age;
			string word, firstName, lastName, country, virusName;
			while (iss >> word) {
				switch (i) {
				case 1:
					citizenId = stoi(word);
					break;
				case 2:
					firstName = word;
					break;
				case 3:
					lastName = word;
					break;
				case 4:
					country = word;
					break;
				case 5:
					age = stoi(word);
					break;
				case 6:
					virusName = word;
					break;
				}
				i++;
			}
			if(!citList->checkIfCitizenVirusExists(citizenId, virusName)){	//Check if citizen exists
				if (citList->getVactinationDate(citizenId, virusName).length() > 0) {
					cout << "ERROR: CITIZEN " << citizenId << " ALREADY VACCINATED ON " << citList->getVactinationDate(citizenId, virusName) << endl;
				}
				else {
					CN* cit = citList->getCitizen(citizenId);
					citList->setVactinationStatus(citizenId, virusName, "YES", todayDate());	//Change record status
					virusList->getNonVaccinatedSkipList(virusName)->deleteCitizen(citizenId); //Delete citizen from Non Vacc skip list
					
					virusList->getVaccinatedSkipList(virusName)->insertCitizen(citizenId, cit);	//Insert citizen to Vacc skip list				
					virusList->getBloomFilter(virusName)->insertCitizenAtBloomFilter(citizenId);	//Insert citizen to bloom filter
				}
			}
			else {
				cout << "Error! Citizen or record not found!" << endl << "Entry success" << endl;
				Entry(citList, countryList, virusNameList, ageList, virusList, citizenId, firstName, lastName, country, age, virusName, "YES", todayDate(), BloomSize);
			}
		}
		else if (fullCommand.substr(0, fullCommand.find(" ")) == "/list-nonVaccinated-Persons") {
			int counter = 0;
			string virusName;
			while (iss >> word) {
				if (counter == 1)
					virusName = word;
				counter++;
			}
			if (!checkForErrors(8, countryList, virusList, citList, 0, virusName, empty)) {	//Check for errors
				node* virus = virusList->getVirus(virusName);
				listNonVaccinatedPersons(virus);
			}
		}
		else {
			cout << "Wrong option. Please re-type your command." << endl;
		}
	}
}

int checkForErrors(int mode, CountryList* countryList, List* virusList, CitizenList* citList, int citizenId, const string& virusName, const string& country){
	switch (mode)
	{
	case 1:
		if (citList->checkIfCitizenExists(citizenId) == -1) {
			if (virusList->checkIfVirusExists(virusName) == -1) {
				cout << "Citizen or virus error!" << endl;
				return -1;
			}
		}
		return 0;
		break;
	case 2:
		if (citList->checkIfCitizenExists(citizenId) == -1) {
			if (virusList->checkIfVirusExists(virusName) == -1) {
				cout << "Citizen or virus error!" << endl;
				return -1;
			}
		}
		return 0;
		break;
	case 3:
		if (citList->checkIfCitizenExists(citizenId) == -1) {
			cout << "Citizen  error!" << endl;
			return -1;
		}
		return 0;
		break;
	case 4:
		if (virusList->checkIfVirusExists(virusName)) {
			cout << "Virus does not exist!" << endl;
			return -1;
		}
		if (country.length() != 0) {
			if (countryList->checkIfCountryExists(country) == NULL) {
				cout << "Country does not exist!" << endl;
				return -1;
			}
		}
		return 0;
		break;
	case 5:
		if (virusList->checkIfVirusExists(virusName)) {
			cout << "Virus does not exist!" << endl;
			return -1;
		}
		if (country.length() != 0) {
			if (countryList->checkIfCountryExists(country) == NULL) {
				cout << "Country does not exist!" << endl;
				return -1;
			}
		}
		return 0;
		break;

	case 8:
		if (virusList->checkIfVirusExists(virusName)) {
			cout << "Virus does not exist!" << endl;
			return -1;
		}
		return 0;
		break;
	}
	return -1;
}

string todayDate(){
	time_t tt;
	struct tm* ti;
	time(&tt);
	ti = localtime(&tt);

	int d = (ti->tm_mday);
	int m = ti->tm_mon + 1;
	int y = ti->tm_year + 1900;

	string date = to_string(d) + "-" + to_string(m) + "-" + to_string(y);
	return date;
}


void ResetData(int& citizenId, string& firstName, string& lastName, string& country, int& age, string& virusName, string& isVactinated, string& dateVaccinated){
	citizenId = 0;
	firstName.clear();
	lastName.clear();
	country.clear();
	age = 0;
	virusName.clear();
	isVactinated.clear();
	dateVaccinated.clear();
}

void Entry(CitizenList* citList, CountryList* countryList, VirusList* virusNameList, AgeList* ageList, List* virusList, int citizenId, const string& firstName, const string& lastName, const string& country, int age, const string& virusName, const string& isVactinated, const string& dateVaccinated, int bfsize){
	//if (citList->checkForSameRecords(citizenId, virusName, isVactinated, dateVaccinated)) {
	if(citList->checkForInconsistentRecords(citizenId, firstName, lastName, country, age, virusName, isVactinated, dateVaccinated)==1){
		//Insert country to country List
		//Inser virusName to virusName List 
		//Insert citizen to citizen List
		//Insert virus to virus List
		//Also, create the first node of each skip list and insert citizens
		Country* cntr;	//Pointer to country
		if ((cntr = countryList->checkIfCountryExists(country)) == NULL) {
			cntr = countryList->InsertCountry(country);
		}
		

		Virus* virus;	//Pointer to virusName
		if ((virus = virusNameList->checkIfVirusExists(virusName)) == NULL) {
			virus = virusNameList->InsertVirus(virusName);
		}

		Age* Age;	//Pointer to age
		if ((Age = ageList->checkIfAgeExists(age)) == NULL) {
			Age = ageList->InsertAge(age);
		}
		if (!citList->checkIfCitizenExists(citizenId)) {
			citList->insertCitizen(1, citizenId, firstName, lastName, cntr, Age, virus, isVactinated, dateVaccinated);	//Insert Citizen
		}
		else {
			citList->insertCitizen(0, citizenId, firstName, lastName, cntr, Age, virus, isVactinated, dateVaccinated);	//Insert Citizen
		}
		
		if (virusList->checkIfVirusExists(virusName)) {	//Insert virus
			virusList->InsertVirus(virus);
		}

		if (virusList->getBloomFilter(virusName) == NULL) {
			virusList->createBloomFilter(virusName, bfsize);
		}
			if (!isVactinated.compare("YES")) {
				if (virusList->getVaccinatedSkipList(virusName) == NULL) {
					virusList->setVaccinatedSkipList(virusName, citList->getCitizen(citizenId));	//Create Vaccinated Skiplist
				}	

				CN* cit = citList->getCitizen(citizenId);
				virusList->getVaccinatedSkipList(virusName)->insertCitizen(citizenId, cit);

				// if (virusList->getBloomFilter(virusName) == NULL) {
				// 	virusList->createBloomFilter(virusName, bfsize);
				// }

				virusList->getBloomFilter(virusName)->insertCitizenAtBloomFilter(citizenId);	//Insert citizen to Bloom Filter
			}
			else {
				if (virusList->getNonVaccinatedSkipList(virusName) == NULL) {
					virusList->setNonVaccinatedSkipList(virusName, citList->getCitizen(citizenId));	//Create Vaccinated Skiplist
				}

				CN* cit = citList->getCitizen(citizenId);
				virusList->getNonVaccinatedSkipList(virusName)->insertCitizen(citizenId, cit);
					
			}

		
		cntr = NULL;
		virus = NULL;
		Age = NULL;
	}
	
	
}

int checkIfDateisBetween(const string& date1, const string& date2, const string& date3){
	//date1
	int year1 = stoi(date1.substr(date1.find_last_of("-") + 1 ));
	int month1 = stoi(date1.substr(date1.find("-") + 1, 2));
	int day1 = stoi(date1.substr(0, 2));

	//date2
	int year2 = stoi(date2.substr(date2.find_last_of("-") + 1));
	int month2 = stoi(date2.substr(date2.find("-") + 1, 2));
	int day2 = stoi(date2.substr(0, 2));
	//date3
	int year3 = stoi(date3.substr(date3.find_last_of("-") + 1));
	int month3 = stoi(date3.substr(date3.find("-") + 1, 2));
	int day3 = stoi(date3.substr(0, 2));

	int toBeCompared = (year2 * 10000) + (month2 * 100) + day2;
	int startDate = (year1 * 10000) + (month1 * 100) + day1;
	int endDate = (year3 * 10000) + (month3 * 100) + day3;

	if (toBeCompared >= startDate && toBeCompared <= endDate) {
		return 1;
	}
	else {
		return -1;
	}
}



void vaccineStatusBloom(List* virusList, int citizenId, const string& virusName){
	int res = virusList->getBloomFilter(virusName)->getVaccinationStatus(citizenId);
	if (!res) {
		cout << "MAYBE" << endl;
	}
	else {
		cout << "NOT VACCINATED" << endl;
	}
	
}

void vaccineStatus(List* virusList, CN* citizen, const string& virusName){
	SkipList* vacc = virusList->getVaccinatedSkipList(virusName);
	int citizenId = citizen->citizenId;

	if (vacc != NULL) {
		if (!vacc->checkIfCitizenExists(citizenId)) {
			CI* temp = citizen->citizenInfo;
			while (temp != NULL) {
				if (!temp->virusName->virus.compare(virusName)) {
					cout << "VACCINATED ON " << temp->dateVaccinated<<endl;
				}
				temp = temp->next;
			}	
		}
		else {
			cout << "NOT VACCINATED" << endl;
		}
	}	
}

void vaccineStatusAll(List* virusList, CitizenList* citList, int citizenId){
	node* temp = virusList->getHead();
	CN* citizen = citList->getCitizen(citizenId);
	while (temp != NULL) {
		SkipList* vacc = temp->VaccinatedSkipList;
		SkipList* nonVacc = temp->NonVaccinatedSkipList;
		CI* virusRecord = citList->getRecord(citizen, temp->virusName->virus);
		if (vacc != NULL) {
			if (!vacc->checkIfCitizenExists(citizenId)) {
				cout << virusRecord->virusName->virus << " " << virusRecord->isVactinated << " " << virusRecord->dateVaccinated << endl;
			}
		}
		if (nonVacc != NULL) {
			if (!nonVacc->checkIfCitizenExists(citizenId)) {
				cout << virusRecord->virusName->virus << " " << virusRecord->isVactinated << endl;
			}
		}

		temp = temp->next;
	}

}

void populationStatus(int mode,CountryList *countryList, CitizenList *citList, node* virus, const string& country, const string& date1, const string& date2){
	//mode=0 no country, mode = 1 country given
	if (!mode) {
		Country* temp = countryList->getHead();
		while (temp != NULL) {
			float count = 0.0, percent = 0.0, population = 0.0;
			if (virus->VaccinatedSkipList != NULL) {
				population = float(virus->VaccinatedSkipList->getPopulationVirus(temp->country));
			}
			if (virus->NonVaccinatedSkipList != NULL) {
				population += float(virus->NonVaccinatedSkipList->getPopulationVirus(temp->country));
			}
			SLN* tempVacc = virus->VaccinatedSkipList->getHead()->next[0];
			while (tempVacc != NULL) {
				if (!tempVacc->citizen->country->country.compare(temp->country)) {
					CI* record = citList->getRecord(tempVacc->citizen, virus->virusName->virus);
					if (checkIfDateisBetween(date1, record->dateVaccinated, date2) == 1) {
						count++;
					}
				}
				tempVacc = tempVacc->next[0];
			}
			if (population != 0)
				percent = (count / population) * (float)(100.00);
			cout <<temp->country << " " << count << " " << setprecision(4) << percent << "%" << endl;

			temp = temp->next;
		}
	}
	else if (mode == 1) {
		float count = 0.0, percent = 0.0, population = 0.0;
		if (virus->VaccinatedSkipList != NULL) {
			population = float(virus->VaccinatedSkipList->getPopulationVirus(country));
		}
		if (virus->NonVaccinatedSkipList != NULL) {
			population += float(virus->NonVaccinatedSkipList->getPopulationVirus(country));
		}
		SLN* tempVacc = virus->VaccinatedSkipList->getHead()->next[0];
		while (tempVacc != NULL) {
			if (!tempVacc->citizen->country->country.compare(country)) {
				CI* record = citList->getRecord(tempVacc->citizen, virus->virusName->virus);
				if (checkIfDateisBetween(date1, record->dateVaccinated, date2) == 1) {
					count++;
				}
			}
			tempVacc = tempVacc->next[0];
		}
		if (population != 0)
			percent = (count / population) * (float)(100.00);
		cout << count << " " << setprecision(4) << percent << "%" << endl;
	}
}

void popStatusByAge(int mode, CitizenList *citList, CountryList *countryList, node* virus, const string& country, const string& date1, const string& date2){
	//mode=0 no country, mode = 1 country given
	if (!mode) {
		Country* temp = countryList->getHead();
		while (temp != NULL) {
			cout << temp->country << endl;
			int minAge = 0, maxAge = 0;
			for (int i = 0; i < 4; i++)
			{
				if (i == 0) {
					minAge = 0;
					maxAge = 19;
				}
				if (i == 1) {
					minAge = 20;
					maxAge = 39;
				}
				if (i == 2) {
					minAge = 40;
					maxAge = 59;
				}
				if (i != 3)
					cout << minAge << "-" << maxAge + 1;
				if (i == 3) {
					minAge = 60;
					maxAge = 120;
					cout << minAge << "+  ";
				}
				float count = 0.0, percent = 0.0, population = 0.0;
				if (virus->VaccinatedSkipList != NULL) {
					population = float(virus->VaccinatedSkipList->getPopulationAgeGroup(temp->country, minAge, maxAge));
				}
				if (virus->NonVaccinatedSkipList != NULL) {
					population += float(virus->NonVaccinatedSkipList->getPopulationAgeGroup(temp->country, minAge, maxAge));
				}
				SLN* tempVacc = virus->VaccinatedSkipList->getHead()->next[0];
				while (tempVacc != NULL) {
					if (!tempVacc->citizen->country->country.compare(temp->country)) {
						if (tempVacc->citizen->age->age >= minAge && tempVacc->citizen->age->age <= maxAge) {
							CI* record = citList->getRecord(tempVacc->citizen, virus->virusName->virus);
							if (checkIfDateisBetween(date1, record->dateVaccinated, date2) == 1) {
								count++;
							}
						}
					}
					tempVacc = tempVacc->next[0];
				}
				if (population != 0)
					percent = (count / population) * (float)(100.00);
				cout << " " << count << " " << setprecision(4) << percent << "%" << endl;
			}
		
			temp = temp->next;
			cout << endl << endl;
		}
		
	}else{
		cout << country << endl;
		int minAge = 0, maxAge = 0;
		for (int i = 0; i < 4; i++) 
		{
			if (i == 0) {
				minAge = 0;
				maxAge = 19;
			}
			if (i == 1) {
				minAge = 20;
				maxAge = 39;
			}
			if (i == 2) {
				minAge = 40;
				maxAge = 59;
			}
			if (i != 3)
				cout << minAge << "-" << maxAge+1;
			if (i == 3) {
				minAge = 60;
				maxAge = 120;
				cout << minAge << "+  ";
			}
			float count = 0.0, percent = 0.0, population = 0.0;
			if (virus->VaccinatedSkipList != NULL) {
				population = float(virus->VaccinatedSkipList->getPopulationAgeGroup(country, minAge, maxAge));
			}
			if (virus->NonVaccinatedSkipList != NULL) {
				population += float(virus->NonVaccinatedSkipList->getPopulationAgeGroup(country, minAge, maxAge));
			}
			SLN* tempVacc = virus->VaccinatedSkipList->getHead()->next[0];
			while (tempVacc != NULL) {
				if (!tempVacc->citizen->country->country.compare(country)) {
					if (tempVacc->citizen->age->age >= minAge && tempVacc->citizen->age->age <= maxAge) {
						CI* record = citList->getRecord(tempVacc->citizen, virus->virusName->virus);
						if (checkIfDateisBetween(date1, record->dateVaccinated, date2) == 1) {
							count++;
						}
					}
				}
				tempVacc = tempVacc->next[0];
			}
			if(population!=0)
				percent = (count / population) * (float)(100.00);
			cout <<" "<< count << " " << setprecision(4) << percent << "%" << endl;
		}
	}

}

void insertCitizen(CitizenList* citList, CountryList* countryList, VirusList* virusNameList, AgeList* ageList, List* virusList, int citizenId, const string& firstName, const string& lastName, const string& country, int age, const string& virusName, const string& isVactinated, const string& dateVaccinated, int bfsize){
	if (!citList->checkIfCitizenExists(citizenId)) {
		if (!citList->checkIfCitizenVirusExists(citizenId, virusName)) {
			if (!citList->getVaccinationStatus(citizenId, virusName).compare("YES")) {
				cout << "CITIZEN " << citizenId << "ALREADY VACCINATED ON " << citList->getVactinationDate(citizenId, virusName) << endl;
			}else{
				if (!isVactinated.compare("YES")) {
					CN* cit = citList->getCitizen(citizenId);
					citList->setVactinationStatus(citizenId, virusName, "YES", dateVaccinated);	//Change record status
					virusList->getNonVaccinatedSkipList(virusName)->deleteCitizen(citizenId); //Delete citizen from Non Vacc skip list

					virusList->getVaccinatedSkipList(virusName)->insertCitizen(citizenId, cit);	//Insert citizen to Vacc skip list				
					virusList->getBloomFilter(virusName)->insertCitizenAtBloomFilter(citizenId);	//Insert citizen to bloom filter
				}
				else {
					cout << "Error.Try again!" << endl;
				}
			}
		}
		else {
			//Entry new virus
			Entry(citList, countryList, virusNameList, ageList, virusList, citizenId, firstName, lastName, country, age, virusName, isVactinated, dateVaccinated, bfsize);
		}
	}
	else {
		//Entry new cit id
		Entry(citList, countryList, virusNameList, ageList, virusList, citizenId, firstName, lastName, country, age, virusName, isVactinated, dateVaccinated, bfsize);
	}
}

void listNonVaccinatedPersons(node* virus){
	if (virus->NonVaccinatedSkipList != NULL) {
		SLN* temp = virus->NonVaccinatedSkipList->getHead()->next[0];
		while (temp != NULL) {
			cout << temp->citizen->citizenId << " " << temp->citizen->firstName << " " << temp->citizen->lastName << " " << temp->citizen->country->country << " " << temp->citizen->age->age << endl;
			temp = temp->next[0];
		}
	}
	else {
		cout << "No record found!" << endl;
	}
}

