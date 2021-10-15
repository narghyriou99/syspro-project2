#include <iostream>
#include <string>
#include "monitorHelp.h"
using namespace std;

void BloomFilter::insertCitizenAtBloomFilter(int citizenId){
	int index = 0, innerIndex = 0;
	int value = 0, newValue = 0, temp = 0;
	string citId = to_string(citizenId);

	for (int i = 0; i < 16; i++) {	//K=16
		index = hash_i(citId, i) % size;	
		value = array[index];
		innerIndex = index % 32;	//Access bit array
		if (!innerIndex) {
			newValue = value | 1;
		}
		else {
			temp = 1;
			temp = temp << innerIndex;
			newValue = value | temp;
		}
		array[index] = newValue;
	}
}

int BloomFilter::getVaccinationStatus(int citizenId){
	int index = 0, innerIndex = 0;
	int value = 0;
	int temp = 0;
	string citId = to_string(citizenId);

	for (int i = 0; i < 16; i++) {
		index = hash_i(citId, i) % size;
		value = array[index];
		innerIndex = index % 32;	//Access bit array
		//temp = value << (32-innerIndex);
		//temp = temp >> 32;
		temp = (value >> innerIndex) & 1;
		if (temp == 0) {
			return -1;	//TRUE NEGATIVE
		}
		temp = 0;
	}

	return 0;	//MAYBE
}

int* BloomFilter::getBloomFilter(){
	return this->array;
}
