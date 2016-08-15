#!/usr/bin/env python
"""
    DiabloHorn http://diablohorn.wordpress.com
    convert pmf.py output to human readable format
"""

import sys
import csv  
import datetime

def convert(csvr,columns):
    csvstdout = csv.writer(sys.stdout, quoting=csv.QUOTE_ALL)
    for rowctr,row in enumerate(csvr):
        timelist = list()
        if rowctr == 0:
            csvstdout.writerow(row)
            continue

        for i in columns:
            ctr = int(i)
            if row[ctr] is not '0':
                row[ctr] = datetime.datetime.fromtimestamp(float(row[ctr])).strftime('%Y-%m-%dT%H:%M:%S')

        csvstdout.writerow(row)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print "Convert pmf.py output to human readable"
        print "{0} {1} {2}".format(sys.argv[0], 'inputfile', 'column1 column2 [...]')
        print "Use '-' for stdin"
        print "{0} input.csv ".format(sys.argv[0])
        sys.exit()
    
    if sys.argv[1] == '-':
        reader = csv.reader(iter(sys.stdin.readline,''))
        convert(reader, sys.argv[2:])
    else:
        with open(sys.argv[1],'r') as f:
            reader = csv.reader(f)
            convert(reader, sys.argv[2:])
