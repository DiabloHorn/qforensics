#!/bin/bash

if [ $# -eq 0 ]
    then
        echo "Converts pmf.py output to body file format"
        echo "$0 <file>"
        exit 1
fi
csvtool -u \| namedcol md5,path,inode,permissions_h,uid,gid,size,atime,mtime,ctime,st_birthtime $1
