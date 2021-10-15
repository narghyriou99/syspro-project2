#ifndef BLOOMFILTER_H_
#define BLOOMFILTER_H_
#include <iostream>
#include "hash.h"
using namespace std;


class BloomFilter {
private:
	int size;	//Real size will be bloomSize/4
	int* array;

public:
	BloomFilter(int Size) {
		
		size = Size / 4;
		array = new int[size];
		//memset(array, 0, size*sizeof(*array));
		memset(array, 0, size*sizeof(int));
	}
	~BloomFilter() {
		delete[] array;
	}

	void insertCitizenAtBloomFilter(int citizenId);
	int getVaccinationStatus(int citizenId);
	/*--------------------------Syspro-2--------------------------*/
	int* getBloomFilter();
};

#endif