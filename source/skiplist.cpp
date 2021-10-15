#include "monitorHelp.h"

using namespace std;

void SkipList::insertCitizen(int citizenId, CN* citizen){
	SLN* temp = head;
	if (head == NULL) {
		head = new SLN(citizenId, getRandomLevel(), citizen);
		return;
	}
	SLN** node = new SLN * [maxLevel + 1];
	memset(node, 0, sizeof(SLN*) * (maxLevel + 1));

	for (int i = level; i >= 0; i--) {
		while (temp->next[i]!=NULL && temp->next[i]->citizenId<citizenId) {
			temp = temp->next[i];
		}
		node[i] = temp;
	}
	temp = temp->next[0];

	if (temp == NULL || temp->citizenId != citizen->citizenId) {
		int randomLevel = getRandomLevel();
		if (randomLevel > level) {
			for (int i = level + 1; i <= randomLevel; i++){
				node[i] = head;
			}
			level = randomLevel;
		}
		temp = new SLN(randomLevel, citizenId, citizen);
		for (int i = 0; i <= randomLevel; i++)
		{
			temp->next[i] = node[i]->next[i];
			node[i]->next[i] = temp;
		}
	}
	delete[] node;
}

int SkipList::getRandomLevel(){
	srand(time(NULL));
	return ((rand() % MAXLEVEL) + 1);
}

int SkipList::checkIfCitizenExists(int citizenId){
	SLN* temp = head;
	for (int i = level; i >= 0; i--) {
		while (temp->next[i]!=NULL && temp->next[i]->citizenId < citizenId) {
			temp = temp->next[i];
		}
	}
	temp = temp->next[0];
	if (temp != NULL && temp->citizenId == citizenId) {
		return 0;
	}
	else {
		return -1;
	}
}

SLN* SkipList::getHead(){
	if(head==NULL)
		return NULL;
	return this->head;
	
}

void SkipList::deleteCitizen(int citizenId){
		SLN* temp = head;
	SLN** node = new SLN * [maxLevel + 1];
	memset(node, 0, sizeof(SLN*) * (maxLevel + 1));

	for (int i = level; i >= 0; i--) {
		while (temp->next[i] != NULL && temp->next[i]->citizenId < citizenId) {
			temp = temp->next[i];
		}
		node[i] = temp;
	}
	temp = temp->next[0];

	if (temp->citizenId == citizenId) {
		for (int i = 0; i <= level; i++) {
			if (node[i]->next[i] != temp)
				break;
			node[i]->next[i] = temp->next[i];
		}
		
		delete temp;
		while (level > 0 && head->next[level] == NULL)
		{
			level--;
		}
	}
	delete[] node;
}

int SkipList::getPopulationVirus(const string& countryName){
	SLN* temp = head->next[0];
	int population = 0;
	while (temp != NULL) {
		if (!temp->citizen->country->country.compare(countryName))
			population++;
		temp = temp->next[0];
	}
	return population;
}

int SkipList::getPopulationAgeGroup(const string& countryName, int minAge, int maxAge){
	SLN* temp = head->next[0];
	int population = 0;
	while (temp != NULL) {
		if (!temp->citizen->country->country.compare(countryName)){
			if (temp->citizen->age->age >= minAge && temp->citizen->age->age <= maxAge)
				population++;
		}
		temp = temp->next[0];
	}
	return population;
}
