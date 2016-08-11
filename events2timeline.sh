#!/bin/bash

if [ $# -eq 0 ]
    then
        echo "You need to provide the events to be timelined"
        exit 1
fi
csvtool col 1- $1 | sort -t, -k1,1
