#include "help.h"

using namespace std;

unsigned long Newdjb2(string& str) {
	unsigned long hash = 5381;
	int len = str.length();
	for (int i = 0; i < len; i++) {
		hash = ((hash << 5) + hash) + str[i]; /* hash * 33 + c */
	}
	return hash;
}

unsigned long Newsdbm(string& str) {
	unsigned long hash = 0;
	int len = str.length();

	for (int i = 0; i < len; i++) {
		hash = str[i] + (hash << 6) + (hash << 16) - hash;
	}

	return hash;
}

unsigned long Newhash_i(string& str, unsigned int i) {
	return Newdjb2(str) + i * Newsdbm(str) + i * i;
}


int FilePath::insertCountryPath(const string& country, const string& path) {
    if (!checkIfCountryExists(country)) {
        cout << "Country "<<country<<" already exists" << endl;
        return -1;
    }
    countyInfo* newNode = new countyInfo;
    newNode->country = country;
    newNode->path = path;
    newNode->next = NULL;
    totalCountries++;
    totalPaths++;

    if (head == NULL || head->country >= newNode->country) {
        newNode->next = head;
        head = newNode;
    }
    else {
        countyInfo* temp = head;
        while (temp->next!=NULL && temp->next->country < newNode->country) {
            temp = temp->next;
        }
        newNode->next = temp->next;
        temp->next = newNode;
    }
    return 0;
}

int FilePath::checkIfCountryExists(const string& country){
    countyInfo* temp = head;
    while (temp != NULL) {
        if (!temp->country.compare(country))
            return 0;
        temp = temp->next;
    }
    return -1;
}

void FilePath::printList(){
    countyInfo *temp = head;
    while(temp!=NULL){
        cout<<"Country: "<<temp->country<<" at path: "<<temp->path<<endl;
        temp = temp->next;
    }
}

int FilePath::getTotalSubDirectories(){
    return this->totalPaths;
}

string FilePath::getCountryAtNode(int nodeNumber){
    string empty;
    countyInfo* temp=head;
    int counter=0;
    while(temp!=NULL){
        if(counter==nodeNumber)
            return temp->path;
        counter++;
        temp=temp->next;
    }
    return empty;
}

countyInfo* FilePath::getHead(){
    return head;
}


void MonitorList::addMonitor(int id){
    monitorNode *temp = new monitorNode;
    temp->id = id;
    temp->next = NULL;
    temp->next_dir = NULL;
    //temp->pid = 0;
    temp->totalSubDirectoriesTohandle=0;
    totalMonitors++;

    if(head == NULL){
        head=temp;
        tail=temp;
        temp=NULL;
    }else{
        tail->next=temp;
        tail=temp;
    }
}


void MonitorList::addCountry(int monitor, const string& filepath){
    monitorNode *temp = head;
    int i=0;
    while(temp!=NULL){  //Go to spesific monitor
        if(i==monitor)
            break;
        i++;
        temp = temp->next;
    }

    //Add sub-node to list 
    subDirectory *newNode = new subDirectory();
    newNode->path = filepath;
    newNode->next=NULL;
    temp->totalSubDirectoriesTohandle++;
    
    if(temp->next_dir==NULL){   //Add as head
        temp->next_dir = newNode;
    }else{      //Add as last node
        subDirectory *innerNode = temp->next_dir;
        while(innerNode->next!=NULL)
            innerNode=innerNode->next;
        innerNode->next=newNode;
    }

}

monitorNode* MonitorList::gethead(){
    return this->head; 
}

void MonitorList::print(){
    monitorNode *temp = head;
    while(temp!=NULL){
        cout<<"Monitor: "<<temp->id<<" .I have "<<temp->totalSubDirectoriesTohandle<<" SubDirectories: ";
        subDirectory *innerTemp=temp->next_dir;
        while(innerTemp!=NULL){
            cout<<innerTemp->path<<", ";
            innerTemp=innerTemp->next;
        }
        temp=temp->next;
        cout<<endl;
    }
}

void MonitorList::deleteRecord(monitorNode *monitorNode){
    subDirectory *temp = monitorNode->next_dir;
    subDirectory *next=NULL;

    while (temp != NULL)
	{
		next = temp->next;
		delete temp;
		temp = next;
	}
}

int MonitorList::getTotalDirectoriesPerMonitor(int monitorNumber){
    monitorNode *temp = head;

    while(temp!=NULL){
        if(temp->id == monitorNumber)
            return temp->totalSubDirectoriesTohandle;
        temp = temp->next;
    }
    return -1;
}

string MonitorList::getSpecificDirectory(int monitorNumber, int directoryNumber){
    string empty;
    monitorNode *temp = head;
    int counter=0;
    while(temp!=NULL){
        if(temp->id == monitorNumber){
            subDirectory *directory = temp->next_dir;
            while(directory!=NULL){
                if(directoryNumber == counter ){
                    return directory->path;
                }
                directory = directory->next;
                counter++;
            }
        }

        temp = temp->next;
    }
    return empty;
}

void MonitorList::insertPid(int monitorNumber, pid_t pid){
    monitorNode *temp = head;
    while(temp!=NULL){
        if(temp->id == monitorNumber){
            temp->pid = pid;
        }
        temp=temp->next;
    }
}

int MonitorList::getMonitor(const string& countryName){
    monitorNode *temp = head;

    while(temp!=NULL){
        subDirectory *innerTemp = temp->next_dir;
        while(innerTemp!=NULL){
            if(innerTemp->path.find(countryName)!= innerTemp->path.npos){
                return temp->id;    //Return monitor id
            }
            innerTemp=innerTemp->next;
        }
        temp=temp->next;
    }
    return -1;
}

void ParentVirusList::insertVirus(const string& virusName){
    virus *temp = new virus();
    temp->bloomFilter=NULL;
    temp->size=bfSize;
    temp->virusName = virusName;
    temp->record=NULL;
    temp->next=NULL;

    totalViruses++;
    if(head == NULL){
        head=temp;
        tail=temp;
        temp=NULL;
    }else{
        tail->next=temp;
        tail=temp;
    }
}

int ParentVirusList::checkIfVirusExists(const string& virusName){
    virus *temp = head;
    while(temp!=NULL){
        if(!temp->virusName.compare(virusName))
            return -1;  //Exists
        temp = temp->next;
    }
    return 0;
}

virus* ParentVirusList::getHead(){
    return this->head;
}

void ParentVirusList::insertBloomFilter(int fd, int bufferSize, const string& virusName){
    virus *temp = head;
    while(temp!=NULL){
        if(!temp->virusName.compare(virusName)){
            int arrayLength = bfSize/4;
            if(temp->bloomFilter==NULL){    //Add it for the first time
                temp->bloomFilter = new int[arrayLength];
                memset(temp->bloomFilter, 0, bfSize);
                //temp->bloomFilter = (int *)receiveBloomFilter(fd, bufferSize, bfSize);
                receiveBloomFilter(fd, bufferSize, bfSize, temp->bloomFilter);
            }else{  //Final BF = (Old BF || Received BF)
                int *arr = new int[arrayLength];
                receiveBloomFilter(fd, bufferSize, bfSize, arr);
                for(int i=0;i<arrayLength;i++){
                    temp->bloomFilter[i] = temp->bloomFilter[i] | arr[i]; 
                }
                delete[] arr;
            }
            return;
        }
        temp = temp->next;
    }
}
int ParentVirusList::getVaccStatus(int citizenId, const string& virusName){
    virus *tempNode = head;
    while(tempNode!=NULL){
        if(!tempNode->virusName.compare(virusName)){
            int index = 0, innerIndex = 0;
            int value = 0;
            int temp = 0;
            string citId = to_string(citizenId);
            for (int i = 0; i < 16; i++) {
                index = Newhash_i(citId, i) % (bfSize/4);
                value = tempNode->bloomFilter[index];
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
        tempNode = tempNode->next;
    }
    return -2;
}

void ParentVirusList::insertRequestRecord(const string& virusName, const string& country, const string& date, int status){
    request *rec = new request();
    rec->country = country;
    rec->date = date;
    rec->status = status;
    rec->next = NULL;

    virus *temp = head;
    while(temp!=NULL){
        if(!temp->virusName.compare(virusName)){    //Find the right node
            if(temp->record==NULL){ //Head
                temp->record = rec;
            }else{
                request *last = temp->record;   //Inner
                while (last->next != NULL)  
                    last = last->next;
                last->next = rec;
            }
            return;
        }
        temp = temp->next;
    }
}


void showOptions(){

    cout << endl;
	cout << "Please select one of these options(1-5):" << endl;
	cout << "--------------------------------------------------------------------------------" << endl;
	cout << "/travelRequest <citizenID> <date> <countryFrom> <countryTo> <virusName>" << endl;
	cout << "/travelStats <virusName> <date1> <date2> <[country]>" << endl;
	cout << "/addVaccinationRecords <country>" << endl;
	cout << "/searchVaccinationStatus <citizenID>" << endl;
	cout << "/exit" << endl;
	cout << "--------------------------------------------------------------------------------" << endl;
	cout << endl;
}


void fileDistribution(MonitorList *list, FilePath* filepath, const string& input_dir, int numOfMonitors){

    int filesCount = 0;
    struct dirent *dir;
    DIR *dp = opendir(input_dir.c_str());
    if(dp){
        string unique_path;
        while((dir=readdir(dp)) != NULL){
            if(!strcmp(dir->d_name, ".") || !strcmp(dir->d_name, "..")) //Reject . and ..
                continue;
            if(dir->d_type == DT_DIR){
                unique_path = input_dir + "/" + dir->d_name;
                filepath->insertCountryPath(dir->d_name, unique_path);   //Add it alphabetically
                filesCount++;
                //cout<<"Path: "<<unique_path<<endl;
            }
        }
        closedir(dp);

        //Define subdirectories to monitors
        monitorNode *temp=list->gethead();
        int i=0, j=0, totalSubDirectories=filepath->getTotalSubDirectories();
        while(totalSubDirectories){
            while(temp!=NULL){
                if(!totalSubDirectories)
                    break;
                list->addCountry(i,filepath->getCountryAtNode(j));
                totalSubDirectories--;
                i++;
                j++;
                temp=temp->next;
                
            }
            temp=list->gethead();
            i=0;
            
        }
       
    }else{
        cout<<"Directory not found!"<<endl; //Didn't find the directory
    }
}

int sendData(int fd, int bufferSize, const string& message){
    
    int length = message.length() + 1;
    char *buffer = new char[length];
    memset(buffer, '\0', sizeof(char)*length);
    strcpy(buffer, message.c_str());

    write(fd, &length, sizeof(int));    //Send Message size

    int sent, n;
    for(sent = 0; sent<length; sent+=n){
        if((length-sent)>bufferSize){
            if((n = write(fd, buffer+sent, bufferSize))==-1)
                return -1;
        }else{
            if((n = write(fd, buffer+sent, length-sent))==-1)
                return -1;
        }  
    }
    delete[] buffer;
    return sent;
}

string readData(int fd, int bufferSize, int messageNo){
    int bytesToRead;
    read(fd, &bytesToRead, sizeof(int));

    int received, n;
    char buffer[bytesToRead];
    for(received = 0; received<bytesToRead; received+=n){
        if((bytesToRead-received) > bufferSize){
            if((n = read(fd, buffer+received, bufferSize))==-1)
            return NULL;
        }else{
            if((n = read(fd, buffer+received, bytesToRead-received))==-1)
            return NULL;
        }
    }
    return string(buffer);
}

int getTotalDirectories(const string& input_dir){
    int filesCount = 0;
    struct dirent *dir;
    DIR *dp = opendir(input_dir.c_str());
    if(dp){
        while((dir=readdir(dp)) != NULL){
            if(!strcmp(dir->d_name, ".") || !strcmp(dir->d_name, "..")) //Reject . and ..
                continue;
            if(dir->d_type == DT_DIR){
                filesCount++;
            }
        }
        closedir(dp);
        return filesCount;
       
    }else{
        cout<<"Directory not found!"<<endl; //Didn't find the directory
    }
    return -1;
}

int writeBloomFilter(int fd, int bufferSize, int bloomFilterSize, int *array){
    
    int sent=0;
    for(int i=0;i<(bloomFilterSize/4);i++){
        sent+=write(fd, &array[i], sizeof(int));
    }
    //cout<<"Sent: "<<sent<<endl;   //Debug
    return sent;

}

int receiveBloomFilter(int fd, int bufferSize, int bloomFilterSize, int arr[]){
    int received=0;
    for(int i=0;i<(bloomFilterSize/4);i++){
        received+=read(fd, &arr[i], sizeof(int));
    }
    //cout<<"Received: "<<received<<endl; //Debug
    return received;
}

void messageDecryption(string message) {
    string deliminter = "*";

    int pos = 0;
    string token;

    while ((pos = message.find(deliminter)) != (int)message.npos) {
        token = message.substr(0, pos);
        if (!token.compare("/")) {
            cout << endl;
        }
        else {
            cout <<token<<" ";
        }
        
        message.erase(0, pos + deliminter.length());
    }

}

int reCreateMonitor(pid_t *pid, int *readArray, int *writeArray, pid_t pidDead, int numOfMonitors, int bufferSize, int bloomFilterSize,  MonitorList *monitorList, ParentVirusList *virusList){
    int i=0;
    for(i=0;i<numOfMonitors;i++){
        if(pid[i]==pidDead)
            break;
    }
    pid[i] = fork();
    monitorList->insertPid(i, pid[i]);
    
    string readPipe, writePipe, path, message;
    char rp[10], wp[10];

    if(pid[i] == -1){   //Error
        perror("Fork");
        exit(-1);
    }else if(pid[i] == 0){  //Child
        //Fix args
        memset(rp, '\0', sizeof(char)*10);
        memset(wp, '\0', sizeof(char)*10);

        readPipe = "fifo" + to_string(i) + to_string(0);
        writePipe = "fifo" + to_string(i) + to_string(1);
        strcpy(rp, readPipe.c_str());
        strcpy(wp, writePipe.c_str());

        char *args[]={(char*)"./monitor", rp, wp, NULL};
        if(execv(args[0], args) == -1){
            perror("Monitor");
            exit(-1);
        }
    }

    write(writeArray[i], &bufferSize, sizeof(int));      //Send Buffer Size
    write(writeArray[i], &bloomFilterSize, sizeof(int));    //Send Bloom Filter Size

    int totalDirToSend = monitorList->getTotalDirectoriesPerMonitor(i);
    write(writeArray[i], &totalDirToSend, sizeof(int));
    for(int j=0;j<totalDirToSend;j++){
        path = monitorList->getSpecificDirectory(i, j);
        sendData(writeArray[i], bufferSize, path);
    }
    int totalViruses, BFexists;
    read(readArray[i], &totalViruses, sizeof(int)); //Get total viruses per monitor
    for(int j=0;j<totalViruses;j++){
        message = readData(readArray[i], bufferSize, 0);
        cout<<"Message:"<<message;
        if(!virusList->checkIfVirusExists(message))
            virusList->insertVirus(message);
        read(readArray[i], &BFexists, sizeof(int));
        if(BFexists==1){    //Reading Bloom Filter
            cout<<" Bloom Filter Exists"<<endl;
            virusList->insertBloomFilter(readArray[i], bufferSize, message);
        }else{
            cout<<" Bloom Filter does not exist"<<endl;           //Go to next virus
        }
    }

    cout<<"Total Viruses "<<totalViruses<<endl;

    if(!readData(readArray[i], bufferSize, 0).compare("READY")){
        cout<<"Monitor "<<i<<" is ready!"<<endl;
    }
   return 1;
}

int checkIfDateIsMoreThan6Months(const string& dateVaccinated, const string& dateTravel) {
    //dateVaccinated
    int year1 = stoi(dateVaccinated.substr(dateVaccinated.find_last_of("-") + 1));
    int month1 = stoi(dateVaccinated.substr(dateVaccinated.find("-") + 1, 2));
    int day1 = stoi(dateVaccinated.substr(0, 2));

    //dateTravel
    int year2 = stoi(dateTravel.substr(dateTravel.find_last_of("-") + 1));
    int month2 = stoi(dateTravel.substr(dateTravel.find("-") + 1, 2));
    int day2 = stoi(dateTravel.substr(0, 2));

    //MinDate
    int year3;
    int month3;
    int day3=day2;
    if (month2 - 6 <= 0){
        int temp = month2 - 6;
        month3 = 12 + temp;
        year3 = year2 - 1;
    }else {
        month3 = month2 - 6;
        year3 = year2;
    }
     
    int toBeCompared = (year1 * 10000) + (month1 * 100) + day1;
    int startDate = (year3 * 10000) + (month3* 100) + day3;
    int endDate = (year2 * 10000) + (month2 * 100) + day2;

    if (toBeCompared >= startDate && toBeCompared <= endDate) {
        return 1;	
    }
    else {
        return -1;
    }
}

int checkIfDateIsBetween(const string& date1, const string& date2, const string& date3){
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

void travelStats(ParentVirusList *virusList, const string& virusName, const string& date1, const string& date2, const string& country, int mode){
    virus *temp = virusList->getHead();
    int accepted=0, rejected=0;
    while(temp!=NULL){
        if(!temp->virusName.compare(virusName)){
            request *record = temp->record;
            if(record!=NULL){
                while(record!=NULL){
                    if(checkIfDateIsBetween(date1, record->date, date2)==1){
                        if(!mode){  //Country given
                            if(!record->country.compare(country)){
                                 if(record->status==1){
                                    accepted++;
                                }else{
                                    rejected++;
                                }
                            }
                        }else{  //All countries
                            if(record->status==1){
                                accepted++;
                            }else{
                                rejected++;
                            }
                        }
                    } 
                    record = record->next;
                }
                cout<<"TOTAL REQUESTS "<<accepted+rejected<<endl;
                cout<<"ACCEPTED "<<accepted<<endl;
                cout<<"REJECTED "<<rejected<<endl;
            }else{
                cout<<"Nothing found!"<<endl;
            }
            return;
        }
        temp = temp->next;
    }
}