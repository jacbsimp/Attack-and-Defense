#!/bin/sh
IFS="
"
sine=''
key='[insert your key]'
for line in $(cat resources.txt); do
# sine="$line" | awk -F : {'print $1'}
sine=$(echo "$line" | awk -F : {'print $2'})
echo $line | awk -F : {'print $1'}
sleep 5
req=$(curl --request GET --url https://www.virustotal.com/api/v3/files/$sine --header 'x-apikey: [insert your key]')
echo "$req" | grep -i "malicious" 
echo "$req" | grep -i -A 7 'names'
echo "--------------------"
done
