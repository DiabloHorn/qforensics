#!/bin/bash

if [ $# -eq 0 ]
    then
        echo "You need to provide the file that needs entropy sorted"
        exit 1
fi
csvtool drop 1 $1 | sort -t, -k22,22
