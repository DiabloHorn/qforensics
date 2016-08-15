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
from Queue import Empty
from multiprocessing import Process, Queue
import logging
import csv

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
CHUNKSIZE = 1024*1024

class file_chunked_operations:
    def __init__(self, algorithms):
        self.algorithms = algorithms
    
    def doall(self, fileloc, filesize):
        self.hashworker = list()
        self.byte_counts = [0] * 256
        self.fileloc = fileloc
        self.results = list()
        self.entropy = 0
        self.magic = '-'

        for algo in self.algorithms:            
            self.hashworker.append(hashlib.new(algo))
          
        for ictr, i in enumerate(self.chunked_reading()):
            if ictr == 0:
                self.magic = magic.from_buffer(i) #comment if no filemagic available
                
            self.hashfile_update(i)
            self.entropy_bytecount(i)
            
        self.hashfile_final()
        self.entropy_shannon(filesize)                                       
    
    def gethashes(self):
        return self.results
    
    def getentropy(self):
        return ['entropy', self.entropy]
    
    def getmagic(self):
        return ['type', self.magic]
                    
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
            self.results.append([hworker.name, hworker.hexdigest()])

    #http://code.activestate.com/recipes/577476-shannon-entropy-calculation/#c3
    def entropy_bytecount(self, filechunk):        
        for b in filechunk:
            self.byte_counts[ord(b)] += 1
            
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

#input format: oct(statoutput.st_mode)[3:]   
def octal2symbolic(octalperms):
    fperms = list()
    symperms = {'0':'---','1':'--x','2':'-w-','3':'-wx','4':'r--','5':'r-x','6':'rw-','7':'rwx'}
    xperms = {'1':'t','2':'s','4':'s'}
    
    for i in octalperms[1:]:
        fperms.append(list(symperms[i]))
    
    if octalperms[0] == '4':
        if fperms[0][2] == '-':
            fperms[0][2] = 'S'
        else:
            fperms[0][2] = 's'
    elif octalperms[0] == '2':
        if fperms[1][2] == '-':
            fperms[1][2] = 'S'
        else:
            fperms[1][2] = 's'
    elif octalperms[0] == '1':
        if fperms[2][2] == '-':
            fperms[2][2] = 'T'
        else:
            fperms[2][2] = 't'
    
    for ictr, i in enumerate(fperms):
        fperms[ictr] = ''.join(i)
    
    #adjust this if you process more than files
    return '-'+''.join(fperms)
    
    
def statfile(fileloc):
    retvals = list()
    statoutput = os.stat(fileloc)
    retvals.append(['atime',str(int(statoutput.st_atime))])
    retvals.append(['mtime',str(int(statoutput.st_mtime))])
    retvals.append(['ctime',str(int(statoutput.st_ctime))])
    retvals.append(['size',str(statoutput.st_size)])  
    retvals.append(['uid',str(statoutput.st_uid)])
    retvals.append(['gid',str(statoutput.st_gid)])      
    retvals.append(['permissions',str(oct(statoutput.st_mode)[3:])])
    retvals.append(['permissions_h', octal2symbolic(str(oct(statoutput.st_mode)[3:]))])
    retvals.append(['inode',str(statoutput.st_ino)])
    retvals.append(['device_id',str(statoutput.st_dev)])
    #the not guaranteed ones
    retvals.append(['st_blocks',getattr(statoutput,'st_blocks','0')])
    retvals.append(['st_blksize',getattr(statoutput,'st_blksize','0')])
    retvals.append(['st_rdev',getattr(statoutput,'st_rdev','0')])
    retvals.append(['st_flags',getattr(statoutput,'st_flags','0')])
    retvals.append(['st_gen',getattr(statoutput,'st_gen','0')])
    retvals.append(['st_birthtime',str(int(getattr(statoutput,'st_birthtime','0')))])
    retvals.append(['st_ftype',getattr(statoutput,'st_ftype','0')])
    retvals.append(['st_attrs',getattr(statoutput,'st_attrs','0')])
    retvals.append(['st_obtype',getattr(statoutput,'st_obtype','0')])
    return retvals
    
def processfile(filelist_q, output_q, algorithms):
    chunked_operations = file_chunked_operations(algorithms)

    while True:
        try:
            fileloc = filelist_q.get(timeout=1)
            if fileloc is None:
                with GLOBAL_LOCK:
                    print >> sys.stderr, "None sentinel"
                    sys.stderr.flush()
                    filelist_q.put(None)
                return

            meta = statfile(fileloc)                        
            chunked_operations.doall(fileloc, float(meta[3][1]))
            hashes = chunked_operations.gethashes()  
            entropy = chunked_operations.getentropy()
            filemagic = chunked_operations.getmagic() #comment if no filemagic available
            output = list()
            output.extend(hashes)
            output.append(['path',fileloc])
            output.extend(meta)
            output.append(entropy)
            output.append(filemagic) #comment if no filemagic available            
            output_q.put(output)
        except Empty:
            with GLOBAL_LOCK:
                print >> sys.stderr, "queue empty"
                sys.stderr.flush()
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
               
def create_workers(filelist_q, output_q, algorithms, amount=get_cpucount()):
    workers = list()
    for ictr, i in enumerate(range(amount)):
        procname = "processfile.%s" % ictr
        p = Process(target=processfile, name=procname, args=(filelist_q, output_q, algorithms))
        p.start()
        workers.append(p)
    return workers                  

def create_loggers(output_q):
    output_p = Process(target=queue_printer, name='output_p', args=(output_q,))
    output_p.start()
    return output_p
    
def walktree_populate_q(filelist_q, treestart):
    for root, dirs, files in os.walk(treestart):
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
    filelist_q.put(None)

def queue_printer(output_q):
    csvstdout = csv.writer(sys.stdout, quoting=csv.QUOTE_ALL)
    printheader = True

    while True:
        header = list()
        body = list()
        try:
            msg = output_q.get(timeout=1)
            if msg is None:
                with GLOBAL_LOCK:
                    print >> sys.stderr, "empty printer queue"
                    sys.stderr.flush()
                return

            for i in msg:
                header.append(i[0])
                body.append(i[1])

            if printheader:
                csvstdout.writerow(header)
                sys.stdout.flush()
                printheader = False
            csvstdout.writerow(body)
            sys.stdout.flush()
        except Empty:
            pass
        except Exception, e:
            with GLOBAL_LOCK:
                print >> sys.stderr, e
                sys.stderr.flush()
                sys.exit()
    return

def readstdin_populate_q(filelist_q, stdin):
    for line in stdin:
        filelist_q.put(line.strip())
    filelist_q.put(None)

def get_args(myargs):
    if len(myargs) < 2:
        print '{0} {1} {2}'.format(myargs[0], '<location>', '[hash_algo hash_algo hash_algo]')
        print 'Available algorithms: {0}'.format(' '.join(hashlib.algorithms))
        print 'Use ctrl-\ if you need a forced stop'
        print 'Use - if you want to read from stdin'
        sys.exit()
    elif len(myargs) == 2:
        return [myargs[1], [DEFAULT_HASH_ALGO]]
    else:
        return [myargs[1], myargs[2:]]

if __name__ == "__main__":
    #enable if you need debugging
    #multiprocessing.log_to_stderr(logging.DEBUG)
    args = get_args(sys.argv)
    filelist_q = Queue(0)
    output_q = Queue(0)

    created_workers = create_workers(filelist_q, output_q, args[1])
    
    if args[0] == '-':
        readstdin_populate_q(filelist_q, sys.stdin)
    else:
        walktree_populate_q(filelist_q, args[0])
    
    output_p = create_loggers(output_q)
    for worker in created_workers:
        worker.join()
    output_q.put(None)
    output_p.join()
