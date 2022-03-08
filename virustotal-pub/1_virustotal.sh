#!/bin/sh
IFS="
"

for line in $(cat filelist.txt); do
echo "$line"
echo "$line:$(curl --request POST --url 'https://www.virustotal.com/vtapi/v2/file/scan' --form 'apikey=[insert your key]' --form "file=@/home/kali/$line" | awk {'print $14'} | sed 's/"//' | sed 's/",//' | tr -d "\t\n\r")" >> resources.txt
sleep 5

done
