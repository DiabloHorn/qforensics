#!/usr/bin/env python
"""
    DiabloHorn http://diablohorn.wordpress.com
    multiprocessing filehashing
"""
import sys
import hashlib
import os
import stat
import multiprocessing
from multiprocessing import Process, Queue

#sudo pip install python-magic
try:
    import magic
except:
    print "sudo pip install python-magic"
    sys.exit()

GLOBAL_LOCK = multiprocessing.Lock()
DEFAULT_HASH_ALGO = 'md5'

def get_cpucount():
    count = 1
    try:
        count = multiprocessing.cpu_count()
    except Exception, e:
        print >> sys.stderr, e
        return count
    return count
    
def chunked_reading(fileloc):
    with open(fileloc, 'rb') as f:
        chunk = f.read(8192*4)
        if chunk != '':
            yield chunk

def hashfile(fileloc, algorithms):
    hashworker = list()
    results = list()
    for algo in algorithms:            
        hashworker.append(hashlib.new(algo))   
    try:
        for i in chunked_reading(fileloc):
            for hworker in hashworker:
                hworker.update(i)
        for hworker in hashworker:
            results.append(hworker.hexdigest())    
        return results        
    except IOError, e:
        with GLOBAL_LOCK:
            print >> sys.stderr, e
            sys.stderr.flush()
    except Exception, e:
        with GLOBAL_LOCK:
            print >> sys.stderr, e
            sys.stderr.flush()
            raise e

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
    while True:
        try:
            if filelist_q.empty():
                return
            fileloc = filelist_q.get(timeout=1)
            hashes = hashfile(fileloc, algorithms)
            meta = statfile(fileloc)
            if hashes:
                with GLOBAL_LOCK:
                    print '{0} {1} {2} {3}'.format(' '.join(hashes), ' '.join(meta), magic.from_file(fileloc,mime=True), fileloc)
                    #comment above and uncomment below if you want to run without file identification
                    #print '{0} {1} {2}'.format(' '.join(hashes), ' '.join(meta), fileloc)
                    sys.stdout.flush()
        except Exception, e:
            with GLOBAL_LOCK:
                print >> sys.stderr, e
                sys.stderr.flush()
                sys.exit()     
               
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
    created_workers = create_workers(filelist_q, args[1])
    for worker in created_workers:
        worker.join()
