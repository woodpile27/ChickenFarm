# ChickenFarm
ChickenFarm is a DDoS attack detection traceability system. It based on the high interaction SSH honeypot. Through the virtual cultivation of malicious software to analyze the type, duration,  victim and controller of the DDoS attack.
## Getting Started
### Prerequisites
* linux system(test on ubuntu 16.04)
* python2.7
* docker and a sshd image(you also can use other image but need to edit cfg)
```bash
docker pull rastasheep/ubuntu-sshd
```
* mongodb
```bash
apt-get install mongodb
```
* redis
```bash
apt-get install redis-server
```
* fprobe
```bash
apt-get install fprobe
```
* scapy, scapy_http, paramiko, pandas, IPy
### Installing
1.  `cp chickenfarm.cfg.default chickenfarm.cfg`
2. Generate keys used by ssh server
  * run `mkdir data`
  * run `ssh-keygen -t rsa`, and put them in `data/`
  * run `ssh-keygen -t dsa`, and put them in `data/`
3. Install python requirements
  * run `pip install -r requirements`
4. Configure the banner of ssh server
  * Edit banner in chickenfarm.cfg
  * It should be same with the ssh banner of sshd contaniner
5. Configure the farm 
  * Edit file_keyword in chickenfarm.cfg. For example if you use a 32bit i386 system, you need to edit it to  `ELF 32-bit LSB, executable, Intel 80386`. If you don't know your system's kernel information, run `uname -a` to see
  * you also can edit the configure of the database if you need
## Running
1. Run
  * run `nohup python main.py &`
2. Stop
  * run `netstat -autpn | grep 22`
  *  `kill pid_number`or`kill -9 pid_number`
3. View logs
  * run `python util/clearlog.py -p log` will remove logs that only have pwd.log, and username:password will write into -l file, default ./pwd.txt 
  * then use playlog.py in util
  * the file hacker download by wget stored in the dir of hackerip in ./log
  * the information of DDos attack were store in mongo, you can see the malware information in table1, see the type, duration and victim in table2
## Built With
* [wetland](https://github.com/ohmyadd/wetland)  -  The honeypot used
## TodoList
* Add visual  with previewing website
* Chcikenfarm dockerized
