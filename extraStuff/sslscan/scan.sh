#!/bin/sh
if [ $# != 1 ];then 
    echo "[usage]scan domain_file"
    exit 1;
else
    for i in `cat $1`
    do 
        echo $i 
        #nc -z `echo www.`$i 443 -w 3
        nc -z $i 443 -w 3
        if [ $? = 0 ];then
            echo "sslscaning"
            sslscan $i | grep 'Accepted' > res/$i&
        else
            echo "skipping"
        fi
    done
fi
