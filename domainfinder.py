import commands, subprocess, sys, getopt, threading, time, Queue, datetime, re, traceback

class WhoisQueue(threading.Thread):
    domainQueue = Queue.Queue()
    stopped = False
    notconnectedDomains = []
    connectedDomains = []
    waitBetweenRequests = 10.0
    curWaitProgress = 0
    waitAfterRefuse = 60
    
    def stop(self):
        self.stopped = True
        
    def queueDomain(self, domain):
        if not self.stopped:
            self.domainQueue.put_nowait(domain)
    
    def isEmpty(self):
        return self.domainQueue.empty()
    
    def qsize(self):
        return self.domainQueue.qsize()
        
    def timeLeft(self):
        seconds = int((self.qsize()*self.waitBetweenRequests)-self.curWaitProgress)
        hours = int(seconds/3600)
        seconds -= hours*3600
        minutes = int(seconds/60)
        seconds -= minutes*60
        return "%02d:%02d:%02d"%(hours,minutes,seconds)
        
    def secondsToWhois(self):
        return int(self.waitBetweenRequests-self.curWaitProgress)
        
    def freeDomain(self, domain, response):
        print "\n\n\n############################################################################"
        print "%s is free!\n"%domain
        print "############################################################################\n\n"
        self.notconnectedDomains.append(domain)
        
    def refusedDomain(self, domain, response):
        print "whois refused, requeueing:\n\n", response
        self.queueDomain(domain)
        self.waitBetweenRequests *= 1.1
        for i in range(self.waitAfterRefuse):
            self.curWaitProgress = (self.waitAfterRefuse-i)*-1
            if not self.stopped:
                time.sleep(1)
    
    def unexpectedResponse(self, domain, response):
        print "\n\n\n############################################################################"
        print "whois unexpected response:\n\n", response
        print "############################################################################\n\n"
        self.notconnectedDomains.append(domain)
        
    def connectedDomain(self, domain, response):
        print "\n             ",domain, "is connected :-("
        self.connectedDomains.append(domain)

    def unavailableDomain(self, domain, response):
        print "\n             ",domain, "is not available"
        self.connectedDomains.append(domain)
    
    def run(self):
        while not self.stopped:
            try:
                domain = self.domainQueue.get(block=True, timeout=1)
                whois = subprocess.Popen('whois '+domain, shell=True, stdout=subprocess.PIPE)
                whois.wait()
                out = whois.stdout.read()
                tld = domain.split('.')[1]
                
                if tld == "de":
                    if not out.find('Status: free') == -1:
                        self.freeDomain(domain, out)
                    elif not out.find('Error: 55000000002') == -1:
                        self.refusedDomain(domain, out)
                    elif not out.find('Status: connect') == -1:
                        self.connectedDomain(domain, out)
                    else:
                        self.unexpectedResponse(domain, out)
                elif tld == "com" or tld == "net":
                    if not out.find('No match for "%s".'%(domain.upper)) == -1:
                        self.freeDomain(domain, out)
                    elif not out.find('Creation Date:') == -1:
                        self.connectedDomain(domain, out)
                    else:
                        self.unexpectedResponse(domain, out)
                elif tld == "eu":
                    if not out.find('Status:	AVAILABLE') == -1:
                        self.freeDomain(domain, out)
                    elif not out.find('Technical:') == -1:
                        self.connectedDomain(domain, out)
                    elif not out.find('Status:	NOT AVAILABLE') == -1:
                        self.unavailableDomain(domain, out)
                    else:
                        self.unexpectedResponse(domain, out)
                elif tld == "org":
                    if not out.find('NOT FOUND') == -1:
                        self.freeDomain(domain, out)
                    elif not out.find('Created On:') == -1:
                        self.connectedDomain(domain, out)
                    elif not out.find('WHOIS LIMIT EXCEEDED') == -1:
                        self.refusedDomain(domain, out)
                    elif not out.find('Name is reserved') == -1:
                        self.unavailableDomain(domain, out)
                    else:
                        self.unexpectedResponse(domain, out)
                elif tld == "me":
                    if not out.find('NOT FOUND') == -1:
                        self.freeDomain(domain, out)
                    elif not out.find('Nameservers:') == -1:
                        self.connectedDomain(domain, out)
                    else:
                        self.unexpectedResponse(domain, out)
                else:
                    print tld+" not supported for whois detection"
                for i in range(int(self.waitBetweenRequests)):
                    self.curWaitProgress = i
                    if not self.stopped:
                        time.sleep(1)
                self.curWaitProgress = 0
            except Queue.Empty:
                pass
            except:
                traceback.print_exc(file=sys.stdout)
        print "checked and connected Domains:"
        print self.connectedDomains
        print "Queued but not checked Domains:"
        queuedDomains = []
        queueEmpty = False
        while not queueEmpty:
            try:
                domain = self.domainQueue.get(block=False)
                queuedDomains.append(domain)
            except Queue.Empty:
                queueEmpty = True
        print queuedDomains
        print "Not connected Domains:"
        print self.notconnectedDomains

class DomainFinder:
    calls = 0
    stopped = False
    
    def __init__(self, min_len, max_len, tld, chars, match,*args,**kwargs):
        self.max_len = int(max_len)
        self.min_len = int(min_len)
        self.tld = tld
        self.chars = chars
        self.whoisThread = WhoisQueue()
        self.whoisThread.start()
        self.match = re.compile(match)
        self.hostOutCheck = re.compile("(.*has address.*)|(.*handled by.*)|(.*NXDOMAIN.*)|(.*NOERROR.*)|(.*SERVFAIL.*)")
        #print min_len, max_len, tld
    
    def stop(self):
        self.whoisThread.stop()
        self.stopped = True
    
    def findDomain(self):
        print "Searching free domains..."
        self.recDomain()
        print "\n\nwaiting for whoisThread to finish"
        while not self.whoisThread.isEmpty() and not self.stopped:
            now = datetime.datetime.now()
            sys.stdout.write('\r'+now.strftime("%H:%M:%S")+
                ' Current queuesize is '+
                str(self.whoisThread.qsize())+
                '    ETA '+
                str(self.whoisThread.timeLeft())+
                '    Next whois in '+
                str(self.whoisThread.secondsToWhois())+
                '         ')
            sys.stdout.flush()
            time.sleep(1)
        print "stopping..."
        self.whoisThread.stop()
        print "\n"

    def recDomain(self, prefix='', charindex=0):
        self.calls += 1
        domain = prefix+self.chars[charindex]
        #print domain, prefix, charindex, self.calls
        if self.min_len <= len(domain) and self.match.match(domain):
            #print domain
            sys.stdout.write('\rTrying '+domain+self.tld+'...')
            sys.stdout.flush()
            process = subprocess.Popen('host '+domain+self.tld, shell=True, stdout=subprocess.PIPE)
            process.wait()
            out = process.stdout.read()
            if process.returncode > 0 and not self.hostOutCheck.match(out):
                print '\r'+domain+self.tld+' -> '+out[:len(out)-1]
                self.whoisThread.queueDomain(domain+self.tld)
        if len(domain) < self.max_len and not self.stopped:
            self.recDomain(domain,0)
        if charindex+1 < len(self.chars) and not self.stopped:
            self.recDomain(prefix,charindex+1)

def usage():
    print "Usage:"
    print "\n--min=1"
    print "    Minimal length of domain (without tld). Default=1)"
    print "\n--max=2"
    print "    Max length of domain (without tld). Default=2)"
    print "\n--chars=\"abcdefghijklmenopqrstuvwxyz0123456789\""
    print "    Charcters to use in domain. Default=\"abcdefghijklmenopqrstuvwxyz0123456789\")"
    print "\n--tld=\".de\""
    print "    Top-Level-Domain to use. Default=\".de\")"
    print "\n--match=\".*\""
    print "    Domain has to match this regex"
    print "\n--help"
    print "    Display this help."
    sys.exit(0)

def main():
    try:
        options, remainder = getopt.getopt(
            sys.argv[1:],
            '',
            ['min=','max=','tld=','chars=','match=','help']
        )
        min_len=1
        max_len=2
        tld = '.de'
        chars = list("abcdefghijklmenopqrstuvwxyz0123456789")
        match = ".*"
        for o, a in options:
            if o == '--min':
                min_len = a
            elif o == '--max':
                max_len = a
            elif o == '--tld':
                tld = a
            elif o == '--chars':
                chars = list(a)
            elif o == '--match':
                match = a
            elif o == '--help':
                usage()
        df = DomainFinder(min_len,max_len,tld,chars,match)
        try:
            df.findDomain()
        except KeyboardInterrupt:
            print "\n\nCaught interrupt, stopping..."
            df.stop()
    except:
        traceback.print_exc(file=sys.stdout)

if __name__ == "__main__":
    main()
