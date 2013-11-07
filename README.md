## mssh
interactive parallel ssh

### why another parallel ssh tool 
there are many parallel ssh tools, but most of them don’t provide interactive capability. The only 3 I know is X-windows based clusterSsh, Mac OS based csshx and chef-ssh.
clusterSsh requires X-windows, csshx require Mac OS and chef-ssh requires Chef server and only connects to servers managed by Chef.

I need to manage many Linux hosts within Amazon (EC2) and within different data centers, I need interactive ssh to many of them at same time, cannot find any existing tool, So I wrote one using Python. 

### feature
* can connect to multiple hosts in parallel and ran command interactively 
* can connect to mulitple hosts by Amazon EC2 instance name (tag)
* can connect to mulitple hosts by lines in a file
* can connect to mulitple hosts by command line parameter
* search/filter hostname/IP using regular expression   

### install

* Install python-paramiko package. You can use “yum install python-paramiko” on Redhat/CentOS or “apt-get install python-paramiko” on Ubuntu/Debain
* (only if you need to access AWS instance using instance name) Install python package boto. You can install it easily using “pip install boto” 
* Make sure you can connect to target host without having to provide password. Using ssh-agent or agent forwarding  ---- search online if you don’t know how to do it

### usage

run the script without , it will give you the correct syntax, like below:

```
Usage: mssh.py [options]

Options:
  -h, --help            show this help message and exit
  -e, --ec2             use EC2 instance
  -f FILE, --file=FILE  use file, each line in file should have format like:
                        'dnsname/ip [alias]'
  -H HOSTS, --hosts=HOSTS
                        input hosts on command line, format
                        'ip1=alias1,ip2=alias2,.....'
  -n PATTERN, --name-match=PATTERN
                        name to match , support Python regex format, when use
                        with -e, will search for EC2 instance tag Name, when
                        use with -f, will search both alias and dnsname/ip
  -u USERNAME, --username=USERNAME
                        username for ssh, default is OS login username
                        (ubuntu)
  -i, --output-ip       output with hostname/IP instead of alias/Tag name
  -l, --list-hosts      list hosts matches

  Caution:
    if we have multiple matches, then the first match wins
```

### license
* free as in free beer and free as in free speech
* use at your own risk