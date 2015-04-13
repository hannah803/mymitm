#!/bin/sh
for i in `cat $1` 
do
echo $i 
nc -z `echo www.`$i 443 -w 3
if [ $? = 0 ];then
echo "sslscaning"
sslscan `echo www.`$i | grep 'Accepted' > res/$i&
else
echo "skipping"
fi
done
