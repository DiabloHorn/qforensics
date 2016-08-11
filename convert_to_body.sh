#!/bin/bash

if [ $# -eq 0 ]
    then
        echo "You need to provide the file that needs converting"
        exit 1
fi
csvtool namedcol md5,path,inode,permissions,uid,gid,size,atime,mtime,ctime,st_birthtime $1 | csvtool drop 1 - 
