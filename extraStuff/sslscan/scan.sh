#!/bin/sh
for i in `cat $1` 
do
echo $i 
if `ping -c1 $i|grep -q '1 received'`;then
echo "sslscaning"
sslscan $i | grep 'Accepted'|grep 'EXP' > sslscan_res/$i&
else
echo "skipping"
fi
done
