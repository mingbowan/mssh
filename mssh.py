#!/usr/bin/env python
import cmd
import sys
import select
import os
import re
import signal
import getpass
import threading

try:
    import paramiko
except:
    print "\n Fatal: Python module/library paramiko is required to run this script\n"
    sys.exit(2)

from optparse import OptionParser, OptionGroup

BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = range(8)

# following from Python cookbook, #475186
def has_colours(stream):
    if not hasattr(stream, "isatty"):
        return False
    if not stream.isatty():
        return False  # auto color only on TTYs
    try:
        import curses
        curses.setupterm()
        return curses.tigetnum("colors") > 2
    except:
        return False
   
has_colours = has_colours(sys.stdout)

def printc(text, colour=WHITE):
        if has_colours:
                seq = "\x1b[1;%dm" % (30 + colour) + text + "\x1b[0m"
                sys.stdout.write(seq + "\n")
        else:
                sys.stdout.write(text + "\n")

def printHost(name, hostlist, noAlias=True, colour=WHITE):
    if not noAlias and hostlist[name] is not None:
        text = hostlist[name]
    else:
        text = name
    text = text + ": "
    if has_colours:
            seq = "\x1b[1;%dm" % (30 + colour) + text + "\x1b[0m"
            sys.stdout.write(seq)
    else:
            sys.stdout.write(text)

def addHost(host, msshObj, lock):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, username=msshObj.username)
        # client.invoke_shell()
        lock.acquire()
        msshObj.connections[host] = client
        lock.release()
    except Exception as e:
        lock.acquire()
        msshObj.err[host] = str(e)
        lock.release()

def do_sftp(host, connections, serverList, noAlias, local, remote):
    try:
        ftp = connections[host].open_sftp()
        x = ftp.put(local, remote)
        printHost(host, serverList, noAlias, MAGENTA)
        printc("copied successfully", CYAN)
    except Exception as e:
        printHost(host, serverList, noAlias, MAGENTA)
        printc("Error: " + str(e), RED)
    finally:
        ftp.close()
            
class Mssh(cmd.Cmd):
    prompt = 'mssh > '
    timeout = 0.01
    connections = {}
    err = {}
    def printHelpString(self):
        printc("\n!sftp <localfile> <removefile> # to sftp/copy files to remote, doesn't support recursive copy\n!list # to list current active servers \n!quit # to quit\n", YELLOW)
    def init(self, serverList, username, noAlias):
        self.username = username
        self.serverList = serverList
        self.noAlias = noAlias
        if len(serverList) == 0:
            printc("no server found/match", RED)
            sys.exit(1)
    def complete(self):
        pass
    def emptyline(self):
        pass

    def preloop(self):
        self.connections = {}
        self.err = {}
        self.activeIn = {}
        printc("login into server(s), please wait....\n", CYAN)
        lock = threading.Lock()
        tids = []
        for host in self.serverList.keys():
            t = threading.Thread(target=addHost, args=(host, self, lock))
            t.start()
            tids.append(t)
        [tid.join() for tid in tids]
        if len(self.err) > 0 :      
            printc("\ncannot connect to below hosts:", RED)
            for host in self.err.keys():
                printc(host + " : " + self.err[host], RED)
        if len(self.connections) == 0:
            print "\ncannot connect to any hosts, quitting ...."
            sys.exit(1)
        printc("\nsuccessfully connected to:", CYAN)
        for host in self.connections.keys():
            printc(host + "\t" + self.serverList[host], CYAN)
        self.printHelpString()
        signal.signal(signal.SIGINT, self.controlC)

    def controlC(self, ignore=None, ingore2=None):        
        for h in self.activeIn.keys():
            try:
                self.activeIn[h].channel.send(chr(3))
            except:
                pass
        
    def quit(self, ignore=None):
        printc("quitting ...", CYAN)
        try:
            for host in self.connections.keys():
                self.connections[host].close()
        finally:
            return True
    def do_help(self, command):
        self.do_shell(command)
    def do_shell(self, command): 
        if command == "quit":
            return self.quit()
        if command == "list":
            for key in sorted(self.connections.keys()):
                printc(key + ":\t" + self.serverList[key], CYAN)
        if command.startswith("sftp "):
            ignore, local, remote = filter(None, command.split(" "))
            if not os.access(local, os.R_OK):
                printc("Error: cannot read local file: " + local, RED) 
                return
            tids = []
            for host in self.connections.keys():                
                t = threading.Thread(target=do_sftp, args=(host, self.connections, self.serverList, self.noAlias, local, remote))
                t.start()
                tids.append(t)
            [tid.join() for tid in tids]            
    do_EOF = quit
    def can_exit(self):
        return True
    def default(self, command):
        todo = self.connections.copy()
        if len(todo) == 0:
            printc("no server left, quitting...", RED)
            return True
        self.activeIn = {}
        stdout = {}
        for host in todo.keys():
            try:
                self.activeIn[host], stdout[host], stderr = todo[host].exec_command(command)                
                stderr.close()
            except Exception as e:
                printc(" SSH Error for " + host + " (" + self.serverList[host] + ") :" + str(e), RED)
                if host in self.connections.keys():
                    del self.connections[host]
                del todo[host]
                if host in self.activeIn.keys():
                    del self.activeIn[host]
        if len(todo) == 0:
            printc("no server left, quitting...", RED)
            return True
        while len(todo) > 0:
            for host in todo.keys():
                try:                
                    while stdout[host].channel.recv_ready():
                        rec = filter(None, stdout[host].channel.recv(4096).split("\n"))  # ## need to enhance here, possible bug
                        for r in rec:
                            printHost(host, self.serverList, self.noAlias, MAGENTA)
                            print r
                    if not stdout[host].channel.recv_ready() and stdout[host].channel.closed:
                        del todo[host]
                        del self.activeIn[host]
                except Exception as e:
                    printc(" SSH Error for " + host + " (" + self.serverList[host] + ") :" + str(e), RED)
                    if host in self.connections.keys():
                        del self.connections[host]
                    del todo[host]
                    if host in self.activeIn.keys():
                        del self.activeIn[host]
def searchEc2(name):
    try:
        from boto.ec2.connection import EC2Connection
        from boto import Version
        if Version < '2.9':
            raise Exception()
    except:
        print "\n Fatal: Python module/library boto >=2.9 is required for -e \n"
        sys.exit(2)

    if 'AWS_ACCESS_KEY_ID' not in os.environ or 'AWS_SECRET_ACCESS_KEY' not in os.environ:
        printc("please set env variable for AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY before using -e, like: ", RED)
        printc(" export AWS_ACCESS_KEY_ID=......", RED)
        printc(" export AWS_SECRET_ACCESS_KEY=....", RED)
        sys.exit(1)
    serverList = {}    
    conn = EC2Connection()
    instances = conn.get_all_instances()
    for i in instances:
        for instance in i.instances:
            if instance.state != "running":
                    continue
            tags = instance.tags
            if tags.has_key("Name") and name.search(tags["Name"]):
                if instance.public_dns_name == "":
                    serverList[instance.private_ip_address] = tags["Name"]
                else:
                    serverList[instance.public_dns_name] = tags["Name"]
    return serverList
def printList(serverList):
    if len(serverList) == 0:
        printc("no server found/match", RED) 
    else:
        printc("found below server(s):", CYAN)
        for key in sorted(serverList.keys()):
            print key + ":\t" + serverList[key]
    print

if __name__ == '__main__':
    serverList = {}
    optp = OptionParser()
    optp.add_option("-e", "--ec2", dest="ec2", action="store_true", default=False, help="use EC2 instance")
    optp.add_option("-f", "--file", dest="file", help="use file, each line in file should have format like: 'dnsname/ip [alias]'")
    optp.add_option("-H", "--hosts", dest="hosts", help="input hosts on command line, format 'ip1=alias1,ip2=alias2,.....'")
    optp.add_option("-n", "--name-match", dest="pattern", help="name to match , support Python regex format, when use with -e, will search for EC2 instance tag Name, when use with -f, will search both alias and dnsname/ip")
    optp.add_option("-u", "--username", dest="username", default=getpass.getuser(), help="username for ssh, default is OS login username (" + getpass.getuser() + ")")
    optp.add_option("-i", "--output-ip", dest="noAlias", action="store_true", default=False, help="output with hostname/IP instead of alias/Tag name")
    optp.add_option("-l", "--list-hosts", dest="listhosts", action="store_true", default=False, help="list hosts matches ")
    group = OptionGroup(optp, "Caution", "if we have multiple matches, then the first match wins\n")
    optp.add_option_group(group)
    opts, args = optp.parse_args()
    ec2 = opts.ec2
    file = opts.file
    hosts = opts.hosts
    pattern = opts.pattern
    
    username = opts.username
    noAlias = opts.noAlias
    listhosts = opts.listhosts
    if pattern is not None:
        try:
            re.compile(pattern)
        except Exception as e:
            printc("\n Error: pattern input error, must be in Python regex format\n", RED)
            sys.exit(1)
    if not ec2 and file is None and hosts is None:
        printc("\n Error: you need at least one of -e, -f or -H\n", RED)
        optp.print_help()
        sys.exit(1)
    if (ec2 and file is not None) or (ec2 and hosts is not None) or (file is not None and hosts is not None):
        printc("\n Error: cannot use -e, -f or -H together\n", RED)
        sys.exit(1)
    if ec2 == True:
        if pattern is None:
            optp.print_help()
            sys.exit(1)
        else:
            serverList = searchEc2(re.compile(pattern))
    if pattern is None:
        pattern = re.compile(".")
    else:
        pattern = re.compile(pattern)
    if hosts is not None:
        for host in filter(lambda x: pattern.search(x), hosts.split(",")):
            t = filter(None, host.split("="))
            if len(t) > 1:
                serverList[t[0]] = t[1]
            else:
                serverList[t[0]] = ""
    if file is not None:
        if not os.access(file, os.R_OK):
            printc(" Error: cannot read file " + file, RED)
        else:
            with open(file) as f:
                for line in f.readlines():                    
                    t = filter(None, line.strip().split(" "))
                    if len(t) >= 2 and (pattern.search(t[0]) or pattern.search(t[1])):
                        serverList[t[0]] = t[1]
                    if len(t) == 1 and (pattern.search(t[0])):
                        serverList[t[0]] = ""
    if listhosts:
        printList(serverList) 
        sys.exit(0)  
    mssh = Mssh()
    mssh.init(serverList, username, noAlias)
    mssh.cmdloop()
        
