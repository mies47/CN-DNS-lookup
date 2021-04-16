# CN-DNS-lookup
This is an implementation of a dns lookup tool like dig.
We use UDP sockets on port 53 to make a connection and do DNS query either by iteration(default) or recursively.
We use google DNS service(8.8.8.8) for recursive queries.
To run and intall first you need to clone the project
Then install the requirements:
```
pip3 install -r requirements.txt
```
For help and options:
```
python3 main.py -h
```
Output:
```
This is a dns lookup tool written for Computer Networks course.
Syntax: python3 main.py [-h|r|R] [-d|io]
options:
h|help                  Show this help menu and exit
d|domain_name           Give domain name you are seeking for its IP
i|input                 The input path of csv file with domainName and recordType
o|output                The path of output.csv
 --note: Either -d or -io option should be specified.
r|record                One of the [A, NS, CNAME, SOA, PTR, MX, TXT, AAAA] record types(default is A)
R|Recur                 Ask to do the query recursively(default is iterative)
```
- To check if the sockets are working alright there are two python scripts ```server.py``` and ```client.py```. You can first run the server and then the client to make sure it's working.
- This script gets root-servers IP from ```root-servers.json``` and records from ```records.py``` on the same directory. Make sure they are available on the same directory as ```main.py```.
- This scripts uses a cache system for queries repeated more than or equal to 3 times. It saves the data in ```dnsCache.json``` on the same directory. Make sure they are available on the same directory as ```main.py```.
- You can also specify a .csv file for input and output for different domains and records. As an example you can see ```test.csv```.

Example usage:
```
python3 main.py -d google.com
```
Output:
```
 -------------------- Question Section --------------------
Generated ID is:        38278
Flags:  0000(No recursion desired, do query by iteration)
Number of questions:    0001
Asking for type A Record!

 
Got results in 0.39056396484375 seconds

 -------------------- Answer Section --------------------
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 38278
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
;; QUESTION SECTION:
;google.com.                    IN      A
;; ANSWER SECTION:
google.com.             300     IN      A       172.217.19.238
```
