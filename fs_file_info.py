#!/usr/bin/env python
"""
    DiabloHorn http://diablohorn.wordpress.com
    multiprocessing single line output for files
        - file hashes
        - file stat output
        - file mimetype
        - file entropy 
        - full filepath
    References:
        http://code.activestate.com/recipes/577476-shannon-entropy-calculation/#c3
        http://stackoverflow.com/a/990646
"""
import sys
import hashlib
import os
import stat
import math
import multiprocessing
from multiprocessing import Process, Queue
import logging

#sudo pip install python-magic
#if you still get errors, make sure you installed the correct lib
#there are multiple magic libs out there :(
try:
    import magic
except:
    print "sudo pip install python-magic"
    sys.exit()

GLOBAL_LOCK = multiprocessing.Lock()
DEFAULT_HASH_ALGO = 'md5'
#make sure it remains compatible with libmagic HOWMANY (1024*256 + SLOP)
CHUNKSIZE = 1024*512

class file_chunked_operations:
    def __init__(self, algorithms):
        self.hashworker = list()
        self.results = list()
        self.algorithms = algorithms
        self.byte_counts = [0] * 256
        self.entropy = 0
        
        for algo in self.algorithms:            
            self.hashworker.append(hashlib.new(algo))
    
    def doall(self, fileloc, filesize):
        self.byte_counts = [0] * 256
        self.fileloc = fileloc
        self.results = list()
        self.entropy = 0
        self.magic = '-'
          
        for ictr, i in enumerate(self.chunked_reading()):
            if ictr == 0:
                self.magic = magic.from_buffer(i)
                
            self.hashfile_update(i)
            self.entropy_bytecount(i)
            
        self.hashfile_final()
        self.entropy_shannon(filesize)                                       
    
    def gethashes(self):
        return self.results
    
    def getentropy(self):
        return self.entropy
    
    def getmagic(self):
        return self.magic
                    
    def chunked_reading(self):
        with open(self.fileloc, 'rb') as f:
            while True:
                chunk = f.read(CHUNKSIZE)
                if chunk != '':
                    yield chunk
                else:
                    break
    
    def hashfile_update(self, filechunk):
        for hworker in self.hashworker:
            hworker.update(filechunk)             
                    
    def hashfile_final(self):
        for hworker in self.hashworker:
            self.results.append(hworker.hexdigest())                    

    #http://code.activestate.com/recipes/577476-shannon-entropy-calculation/#c3
    def entropy_bytecount(self, filechunk):    
        for bytenum in range(256):
            ctr = 0
            for b in filechunk:
                if ord(b) == bytenum:
                    ctr += 1
            self.byte_counts[bytenum] = self.byte_counts[bytenum] + ctr

    #http://stackoverflow.com/a/990646    
    def entropy_shannon(self, filesize):
        if self.byte_counts:
            for count in self.byte_counts:
                # If no bytes of this value were seen in the value, it doesn't affect
                # the entropy of the file.
                if count == 0:
                    continue
                # p is the probability of seeing this byte in the file, as a floating-
                # point number
                p = 1.0 * count / filesize
                self.entropy -= p * math.log(p, 2)

def get_cpucount():
    count = 1
    try:
        count = multiprocessing.cpu_count()
    except Exception, e:
        print >> sys.stderr, e
        return count
    return count    
    
def statfile(fileloc):
    """
    posix.stat_result(st_mode=33188, st_ino=479, st_dev=26L, st_nlink=1, st_uid=501, st_gid=20, st_size=124, 
    st_atime=1470523937, st_mtime=1470523937, st_ctime=1470523937)
    """
    retvals = list()
    statoutput = os.stat(fileloc)
    retvals.append(str(oct(stat.S_IMODE(statoutput.st_mode))))
    retvals.append(str(statoutput.st_ino))
    retvals.append(str(statoutput.st_dev))
    retvals.append(str(statoutput.st_uid))
    retvals.append(str(statoutput.st_gid))
    retvals.append(str(statoutput.st_size))
    retvals.append(str(statoutput.st_atime))
    retvals.append(str(statoutput.st_mtime))
    retvals.append(str(statoutput.st_ctime))
    return retvals
    
def processfile(filelist_q, algorithms):
    chunked_operations = file_chunked_operations(algorithms)
    while True:
        try:
            if filelist_q.empty():
                with GLOBAL_LOCK:
                    print "empty queue"
                    sys.stdout.flush()                
                return
            fileloc = filelist_q.get(timeout=1)
            #removeme
            with GLOBAL_LOCK:
                print "working on %s" % fileloc
                sys.stdout.flush()
            meta = statfile(fileloc)            
            chunked_operations.doall(fileloc, float(meta[5]))
            hashes = chunked_operations.gethashes()  
            entropy = chunked_operations.getentropy()
            filemagic = chunked_operations.getmagic()          
            with GLOBAL_LOCK:
                print '{0} {1} {2} {3} {4}'.format(' '.join(hashes), ' '.join(meta), filemagic, entropy, fileloc)
                #comment above and uncomment below if you want to run without file identification
                #print '{0} {1} {2} {3}'.format(' '.join(hashes), ' '.join(meta), entropy, fileloc)
                sys.stdout.flush()
        except IOError, e:
            if e.errno == 13:
                with GLOBAL_LOCK:           
                    print >> sys.stderr, e
                    sys.stderr.flush()
            else:
                with GLOBAL_LOCK:
                    print >> sys.stderr, e
                    sys.exit()
    return  
               
def create_workers(filelist_q, algorithms, amount=get_cpucount()):
    workers = list()
    for i in range(amount):
        p = Process(target=processfile, args=(filelist_q, algorithms))
        p.start()
        workers.append(p)
    return workers                  

def get_args(myargs):
    if len(myargs) < 2:
        print '{0} {1} {2}'.format(myargs[0], '<location>', '[hash_algo hash_algo hash_algo]')
        print 'Available algorithms: {0}'.format(' '.join(hashlib.algorithms))
        print 'Use ctrl-\ if you need a forced stop'
        sys.exit()
    elif len(myargs) == 2:
        return [myargs[1], [DEFAULT_HASH_ALGO]]
    else:
        return [myargs[1], myargs[2:]]
        
if __name__ == "__main__":
    multiprocessing.log_to_stderr(logging.DEBUG)
    args = get_args(sys.argv)
    filelist_q = Queue()
    for root, dirs, files in os.walk(args[0]):
        for f in files:
            fullpath = os.path.join(root,f)
            try:
                if os.path.isfile(fullpath) and not os.path.islink(fullpath):
                    filelist_q.put(fullpath) 
            except Exception, e:
                with GLOBAL_LOCK:
                    print >> sys.stderr, e
                    sys.stderr.flush()
                    sys.exit()
    created_workers = create_workers(filelist_q, args[1])
    for worker in created_workers:
        worker.join()
