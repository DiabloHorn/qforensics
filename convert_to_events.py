#!/usr/bin/env python
"""
    DiabloHorn http://diablohorn.wordpress.com
    convert pmf.py output to events
"""

import sys
import csv  
             
def convert(csvr):   
    csvstdout = csv.writer(sys.stdout, quoting=csv.QUOTE_ALL)
    for rowctr,row in enumerate(csvr):
        timelist = list()
        if rowctr == 0:
            atime = row.index('atime')
            mtime = row.index('mtime')
            ctime = row.index('ctime')
            crtime = row.index('st_birthtime')
            continue

        timelist.append([row[atime],'atime'])
        timelist.append([row[mtime],'mtime'])
        timelist.append([row[ctime],'ctime'])
        if row[crtime] is not '-':
            timelist.append([row[crtime],'crtime'])
        
        for i in timelist:
            outputlist = list()
            outputlist.extend(i)
            outputlist.extend(row)
            csvstdout.writerow(outputlist)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Convert pmf.py output to events"
        print "{0} {1}".format(sys.argv[0], 'input-file')
        print "Use '-' for stdin"
        print "{0} input.csv"
    
    if sys.argv[1] == '-':
        reader = csv.reader(iter(sys.stdin.readline,''))
        convert(reader)
    else:
        with open(sys.argv[1],'r') as f:
            reader = csv.reader(f)
            convert(reader)
            
