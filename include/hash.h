#ifndef HASH_H_
#define HASH_H_

#include <iostream>

using namespace std;

unsigned long djb2(string& str);
unsigned long sdbm(string& str);
unsigned long hash_i(string& str, unsigned int i);


#endif