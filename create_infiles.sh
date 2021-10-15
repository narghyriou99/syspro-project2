#!/bin/bash
#./create_infiles.sh inputFile input_dir numFilesPerDirectory

echo "I was called with $# parameters"

NUM=$#

#check that the correct args where given
if [ $# != 3 ]
then
	echo "Usage: ./create_infiles.sh <inputFile> <input_dir> <numFilesPerDirectory>"
	exit 1
fi

#get the file names
INPUTFILE=$1
INPUT_DIR=$2
NUMOFFILES=$3

#check if input file exists
if [  ! -f "$INPUTFILE" ]
then
	echo "$1 does not exist"
	exit 1
fi

#check if input_dir exists
if [ -d "$INPUT_DIR" ]
then
	echo "$2 already exists"
	exit 1
else
	#Create the first folder
	echo "Creating input_dir directory"
	mkdir -p $INPUT_DIR
fi

declare -a country_array
country_counter=0

#Create sub-directories
while IFS= read -r line; do
	result=$(echo $line | cut -d " " -f 4)

	if [[ " ${country_array[*]} " != *" $result "* ]];
	then
    	#echo "array contains $result"
	#else
		country_array[country_counter]=$result
		country_counter=$(( $country_counter + 1))
		mkdir "$2"/"$result"
	fi
	
done < $1

#Create one txt file per subdirectory
while IFS= read -r line; do
	result=$(echo $line | cut -d " " -f 4)
	if [[ " ${country_array[*]} " == *" $result "* ]];
	then
		touch  "$2"/"$result"/"general.txt"
		echo "$line">>"$2"/"$result"/"general.txt"
	fi

done < $1

#Split it!
for (( i=0; i < $country_counter; i++ ))
do
	#Create txt files in every sub directory
	country=${country_array[$i]}
	for (( j=1; j <= $3; j++ ))
	do
		touch "$2"/"$country"/"$country"-"$j".txt 
	done

	counter=1
	while IFS= read -r line; do
		#RR
		if [ $counter -eq $(( $NUMOFFILES + 1)) ]
		then
			counter=1
		fi
		echo "$line" >> "$2"/"$country"/"$country"-"$counter".txt

		counter=$(( $counter + 1))

	done < "$2"/"$country"/"general.txt"

	rm "$2"/"$country"/"general.txt"
done

echo "All done..."