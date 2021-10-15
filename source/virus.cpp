#include "monitorHelp.h"

using namespace std;

void List::InsertVirus(Virus* virusName){
	node *temp = new node;
	temp->virusName = virusName;
	temp->next = NULL;
	temp->VaccinatedSkipList = NULL;
	temp->NonVaccinatedSkipList = NULL;
	temp->bloomFilter = NULL;
	sumOfNodes++;

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

int List::checkIfVirusExists(const string& virusName){
	if (head == NULL) {
		return -1;	//Skip 
	}
	else {
		node* temp = head;
		while (temp != NULL) {
			if (!temp->virusName->virus.compare(virusName)) {
				return 0;	//Virus Exists
			}
			temp = temp->next;
		}
	}
	return -1;	//Doesnt exist
}

void List::printList(){
	node* temp = head;
	cout << "Total viruses: " << sumOfNodes << endl;
	while (temp != NULL) {
		cout << "Virus: " << temp->virusName->virus << endl;
		temp = temp->next;
	}
}

void List::setVaccinatedSkipList(const string& virusName, CN* citizen){
	node* temp = head;
	while (temp != NULL) {
		if (!temp->virusName->virus.compare(virusName)) {
			temp->VaccinatedSkipList = new SkipList(citizen);
		}
		temp = temp->next;
	}
	
}

void List::setNonVaccinatedSkipList(const string& virusName, CN* citizen){
	node* temp = head;
	while (temp != NULL) {
		if (!temp->virusName->virus.compare(virusName)) {
			temp->NonVaccinatedSkipList = new SkipList(citizen);
		}
		temp = temp->next;
	}
}

SkipList* List::getVaccinatedSkipList(const string& virusName){
	node* temp = head;
	while (temp != NULL) {
		if (!temp->virusName->virus.compare(virusName)) {
			return temp->VaccinatedSkipList;
		}
		temp = temp->next;
	}
	return NULL;
	
}

SkipList* List::getNonVaccinatedSkipList(const string& virusName){
	node* temp = head;
	while (temp != NULL) {
		if (!temp->virusName->virus.compare(virusName)) {
			return temp->NonVaccinatedSkipList;
		}
		temp = temp->next;
	}
	return NULL;
}

BloomFilter* List::getBloomFilter(const string& virusName){
	node* temp = head;
	while (temp != NULL) {
		if (!temp->virusName->virus.compare(virusName)) {
			return temp->bloomFilter;
		}
		temp = temp->next;
	}
	return NULL;
}

void List::createBloomFilter(const string& virusName, int bfSize){
	node* temp = head;
	while (temp != NULL) {
		if (!temp->virusName->virus.compare(virusName)) {
			temp->bloomFilter = new BloomFilter(bfSize);
		}
		temp = temp->next;
	}
}

void List::deleteSkipLists(){
	node* temp = head;
	while (temp != NULL) {
		if (temp->VaccinatedSkipList != NULL) {
			delete temp->VaccinatedSkipList;
			temp->VaccinatedSkipList = NULL;
		}
		if (temp->NonVaccinatedSkipList != NULL) {
			delete temp->NonVaccinatedSkipList;
			temp->NonVaccinatedSkipList = NULL;
		}
		temp = temp->next;
	}
}

node* List::getHead(){
	return this->head;
}

node* List::getVirus(const string& virusName){
	node* temp = head;
	while (temp != NULL) {
		if (!temp->virusName->virus.compare(virusName)) {
			return temp;
		}
		temp = temp->next;
	}
	return NULL;
}

void List::sendBloomFilter(int fd, int bufferSize, int bloomFilterSize){
	write(fd, &sumOfNodes, sizeof(int)); //Write total number of viruses
	node *temp = head;
	int status;
	string message;
	while(temp!=NULL){	//Write VirusNames
		message = temp->virusName->virus;
		sendData(fd, bufferSize, message);
		if(temp->bloomFilter==NULL){
			status=-1;
			write(fd, &status, sizeof(int));	//Indicate to parent process that there is no Bloom Filter
		}else{
			status=1;
			write(fd, &status, sizeof(int));	//Indicate to parent process that he has to read Bloom Filter
			writeBloomFilter(fd, bufferSize, bloomFilterSize, temp->bloomFilter->getBloomFilter());
		}
		temp = temp->next;
	}

}




