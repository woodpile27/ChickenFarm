import time
import redis
import pymongo
import hashlib
import subprocess
import random
import threading
import pandas as pd
from IPy import IP as IPY
from operator import itemgetter
from scapy.all import *
import scapy_http.http as HTTP
from config import *

#FILE_SLIM = (100*1024*1024) # 100Mb
REDIS = redis.Redis(host=REDIS_HOST, port=REDIS_PORT)
mongo_client = pymongo.MongoClient(MONGO_URI)
mongodb = mongo_client[MONGO_DB]

INTERVALS = 5 # 3s
THRESHOLD = 1000
UDP_AMP = {53: 'DNS_AMP', 389: 'CLDAP_AMP', 1900: 'SSDP_AMP', 123: 'NTP_AMP', 19: 'CharGEN_AMP', \
           11211: 'MEMCACHE_AMP', 1701: 'L2TP_AMP', 111: 'Portmap_AMP', 161: 'SNMP_AMP', \
           6881: 'BitTorrent_AMP', 6882: 'BitTorrent_AMP', 6883: 'BitTorrent_AMP', \
           6884: 'BitTorrent_AMP', 6885: 'BitTorrent_AMP', 6886: 'BitTorrent_AMP', \
           6887: 'BitTorrent_AMP', 6888: 'BitTorrent_AMP', 6889: 'BitTorrent_AMP'}
TCP_FLOOD = {'S': 'SYN_FLOOD', 'A': 'ACK_FLOOD', 'SA': 'SYN_ACK_FLOOD', 'R': 'RST_FLOOD', \
             'SR': 'SYN_RST_FLOOD', '': 'EMPTY_TFLAGS_FLOOD'}
TREE = {'protocol': {'icmp': 'ICMP_FLOOD','udp': {'isamp': {'yes': {'dstport': UDP_AMP}, \
       'no': {'dns_flood': {'yes': 'DNS_FLOOD', 'no': {'smallpack': {'yes': 'SMALL_PACKAGE_FLODD', \
       'no': 'PLAIN_FLOOD'}}}}}},'tcp': {'fake_ip': {'yes': {'isamp': {'yes': 'ACK_AMP_FLOOD', \
       'no': {'tcpflag': TCP_FLOOD}}}, 'no': {'dstport': {80: 'CC_FLOOD', 443: 'SSL_FLOOD'}}}}}}


class FileCapture(object):

    def __init__(self, docker_name, docker_ip, evt, tServer):
        self.iface = 'docker0'
        self.docker_name = docker_name
        self.docker_ip = docker_ip
        self.file_list = {}
        self.evt = evt
        self.tServer = tServer
	REDIS.flushdb()

    def change_docker(self, new_name, docker_ip):
        self.docker_name = new_name
        self.docker_ip = docker_ip
        self.file_list = {}

    def sniff_file(self):
        sniff(iface=self.iface, prn=self.save_to_redis, filter='host {} and tcp and port 80'.format(self.docker_ip), store=False)

    def save_to_redis(self, pkt):
        data = str(pkt)
        try:
            REDIS.rpush(self.docker_name, data)
        except Exception:
            print 'save to redis failed'

    def get_from_redis(self):
        while True:
            try:
                data = REDIS.lpop(self.docker_name)
            except Exception:
                print 'get from redis error'
            if data:
                try:
		    pkt = Ether(data)
		    self.parse(pkt)
                except Exception, e:
		    print e
            else:
                time.sleep(2)

    def parse(self, pkt):
        id = "%s:%d" % (pkt[IP].dst, pkt[TCP].dport)
        if HTTP.HTTPRequest in pkt:
            id = "%s:%d" % (pkt[IP].src, pkt[TCP].sport)
            hacker_ip = self.tServer.cfg.get("wetland", "hacker_ip")
            path = pkt.Host + pkt.Path
            file_name = pkt.Path.split('/')[-1]
            file_name = str(random.randrange(1000,9999)) if file_name == '' else file_name
            self.file_list[id] = {
                                  'name': file_name,
                                  'path': path,
                                  'hacker_ip': hacker_ip
                                  }
        elif HTTP.HTTPResponse in pkt:
            try:
                content_leng = int(pkt.sprintf("%HTTPResponse.Content-Length%")[2:-1])
            except:
                content_leng = int(pkt.sprintf("%HTTPResponse.Status-Line%").split()[-1][:-1])
            seq = pkt.seq
            ack = pkt.ack
            self.file_list[id].update({
                                'file_length': content_leng,
                                'ack': ack
                                })
            if Raw in pkt:
                load = str(pkt[Raw].load)
                data = {'seq': seq, 'data': load}
		if self.file_list[id].has_key('datas'):
		    self.file_list[id]['datas'].append(data)
		    self.file_list[id]['now_length'] += len(load)
		else:
                    self.file_list[id].update({
                                       'now_length': len(load),
                                       'datas': [data]
                                       })
                if self.file_list[id]['now_length'] == content_leng:
                    self.save_to_file(self.file_list[id])
            else:
                self.file_list[id].update({
                                    'now_length': 0,
                                    'datas': []
                                    })
        elif Raw in pkt and pkt.sport == 80:
            seq = pkt.seq
            ack = pkt.ack
            if id in self.file_list.keys():
                load = str(pkt[Raw].load)
                data = {'seq': seq, 'data': load}
		if self.file_list[id].has_key('datas'):
                    self.file_list[id]['datas'].append(data)
		    self.file_list[id]['now_length'] += len(load)
		else:
		    self.file_list[id]['datas'] = [data]
                    self.file_list[id]['now_length'] = len(load)
		if self.file_list[id].has_key('ack'):
                    if self.file_list[id]['now_length'] == self.file_list[id]['file_length']:
                        self.save_to_file(self.file_list[id])
		        self.file_list.pop(id)
        else:
            pass

    def save_to_file(self, file_infor):
        rows = sorted(file_infor['datas'], key=itemgetter('seq'))
        data = ''.join([i['data'] for i in rows])
        file_name = "./log/%s/%s" % (file_infor['hacker_ip'], file_infor['name'])
        with open('%s' % file_name, 'wb') as f:
            f.write(data)
        sha256 = self.file_SHA256(data)
        file_type = self.file_type(file_name)
        flag = self.check_file_type(file_type)
        self.save_to_mongo(file_infor, sha256, file_type, flag)

    def file_SHA256(self, data):
        hsha = hashlib.sha256()
        hsha.update(data)
        return hsha.hexdigest()

    def file_type(self, name):
        out_bytes = subprocess.check_output(['file', name])
        return out_bytes.split(':')[-1].strip()

    def check_file_type(self, file_type):
        for keyword in KEYWORD.split(','):
            if keyword.strip() not in file_type:
                return None
        self.evt.set()
        return 1

    def save_to_mongo(self, data, sha256, file_type, flag):
        import time
        time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        result = {
                'docker': self.docker_name,
                'docker_ip': self.docker_ip,
                'hacker_ip': data['hacker_ip'],
                'path': data['path'],
                'name': data['name'],
                'time': time,
                'sha256': sha256,
                'type': file_type,
                'flag': flag
                }
        try:
            if mongodb[MONGO_TABLE1].insert(result):
                print 'save to mongodb successful'
        except Exception:
            print 'save to mongodb failed'

class DDosMonitor(object):

    def __init__(self, port, docker_ip):
        self.flow_datas = []
        self.monitor = docker_ip
        self.start(port)

    def start(self, port):
        self.thread_start(self.capture, port)
        self.thread_start(self.timer)

    def capture(self, port):
        sniff(iface='lo', prn=self.parse, filter='udp and port %s' % str(port), store=False)

    def timer(self):
        while True:
            time.sleep(INTERVALS)
            self.reset()

    def reset(self):
        cp = self.flow_datas
        self.flow_datas = []
        self.judge(cp)

    def parse(self, pkt):
        try:
            netflow = NetflowHeader(pkt.load)
            count = netflow.count
            for i in range(0, count):
                flow = netflow[NetflowRecordV5][i]
                data = [':'.join([flow.src, str(flow.srcport)]), ':'.join([flow.dst, str(flow.dstport)]), \
                        flow.dpkts, flow.dOctets, flow.first, flow.last, flow.src, flow.dst, flow.srcport, flow.dstport, \
                        flow.sprintf("%NetflowRecordV5.tcpFlags%"), flow.sprintf("%NetflowRecordV5.prot%")]
                self.flow_datas.append(data)
        except Exception, e:
            print e

    def judge(self, datas):
        columns = ['src', 'dst', 'dpkts', 'dOctets', 'first', 'last', 'srcip', 'dstip', 'srcport', 'dstport', 'tcpFlags', 'prot']
        df = pd.DataFrame(datas , columns=columns)
        #flownum = float(df.shape[1])
        #expectation = df.groupby('prot').size().apply(lambda x: x*x/flownum).sum()
        total_pkts = df['dpkts'].sum()
        if total_pkts > THRESHOLD:
            self.analysis(df)


    def analysis(self, df):
        start_time = df['first'][0]
        max_prot = df.groupby('prot')['dOctets'].agg('sum').idxmax()
        dst_group = df.groupby('dst')['dOctets'].agg('sum').sort_values(ascending=False).index
        max_dst = ''
        for dst in dst_group:
            if IPY(dst.split(':')[0]).iptype() == 'PUBLIC':
                max_dst = dst
                break
        max_dstport = df.groupby('dstport')['dpkts'].agg('sum').idxmax()
        max_src = df.groupby('src')['dpkts'].agg('sum').idxmax()
        # UDP
        if max_prot == 'udp':
            maxprot_df = df[df.prot == max_prot]
            dstip_ent = self.calcShannonEnt(maxprot_df.groupby('dstip')['dpkts'].agg('sum'))
            srcip_ent = self.calcShannonEnt(maxprot_df.groupby('srcip')['dpkts'].agg('sum'))
            maxdst_df = df[(df.prot == max_prot) & (df.dst == max_dst)]
            pkts = maxdst_df['dpkts'].sum()
            pkt_bytes = maxdst_df['dOctets'].sum() / pkts
            udp_amp = 'yes' if max_dstport in UDP_AMP.keys() and dstip_ent > 1.5 and srcip_ent < 0.8 else 'no'
            dns_flood = 'yes' if max_dstport == 53 else 'no'
            small_pack = 'yes' if pkt_bytes < 200 else 'no'
            labels = ['protocol', 'isamp', 'dstport', 'dns_flood', 'smallpack']
            vec = [max_prot, udp_amp, max_dstport, dns_flood, small_pack]
            ddostype = self.classify(TREE, labels, vec)
        # TCP
        elif max_prot == 'tcp':
            dst_df = df[(df.prot == max_prot) & (df.dst == max_dst)]
            srcip_group = dst_df.groupby('srcip')['dpkts'].agg('sum')
            srcip_ent = self.calcShannonEnt(srcip_group)
            maxsrcip_pub = IPY(srcip_group.idxmax()).iptype() == 'PUBLIC'
            dstip_ent = self.calcShannonEnt(df[df.prot == max_prot].groupby('dstip')['dpkts'].agg('sum'))
            tcpflags_df = dst_df.groupby('tcpFlags')['dpkts'].agg('sum')
            max_tcpflag = tcpflags_df.idxmax()
            #max_tcpflag = tcpflags_df.max()
            fake_ip = 'yes' if srcip_ent > 4 or (srcip_ent < 0.8 and maxsrcip_pub) else 'no'
            tcp_amp = 'yes' if dstip_ent > 1.5 and srcip_ent < 0.8 else 'no'
            max_dstport = int(max_dst.split(':')[-1])
            labels = ['protocol', 'fake_ip', 'isamp', 'tcpflag', 'dstport']
            vec = [max_prot, fake_ip, tcp_amp, max_tcpflag, max_dstport]
            ddostype = self.classify(TREE, labels, vec)
        #imcp
        else:
            ddostype = max_prot.upper() + '_FLOOD'
        victim = max_src if 'AMP' in ddostype else max_dst
        self.save_to_mongo(ddostype, victim, start_time)

    def calcShannonEnt(self, dataSet):
        from math import log
        numEntries = dataSet.sum()
        shannonEnt = 0.0
        for value in dataSet:
            prob = float(value)/numEntries
            shannonEnt -= prob * log(prob,2)
        return shannonEnt

    def classify(self, inputTree, featLabels, testVec):
        firstStr = inputTree.keys()[0]
        secondDict = inputTree[firstStr]
        featIndex = featLabels.index(firstStr)
        key = testVec[featIndex]
        valueOfFeat  = secondDict[key]
        if isinstance(valueOfFeat, dict):
            classLabel = self.classify(valueOfFeat, featLabels, testVec)
        else:
            classLabel = valueOfFeat
        return classLabel

    def save_to_mongo(self, ddostype, victim, start_time):
        result = {
                  'docker_ip': self.monitor,
                  'attacked_ip': victim.split(':')[0],
                  'attacked_port': int(victim.split(':')[-1]),
                  }
        record = mongodb[MONGO_TABLE2].find_one(result, sort=[('end_time', pymongo.DESCENDING)])
        if record and start_time - record['end_time'] < 90:
            end_time = record['end_time']
            mongodb[MONGO_TABLE2].update({'end_time': end_time}, {'$set': {'endtime': start_time}})
        else:
            try:
                result.update({'start_time': start_time, 'end_time': start_time})
                if mongodb[MONGO_TABLE2].insert(result):
                    print 'save to mongodb successful'
            except Exception:
                print 'save to mongodb failed'

    def thread_start(self, target, *args):
        thread = threading.Thread(target=target, args = args)
        thread.setDaemon(True)
        thread.start()

class C2Monitor(object):

    def __init__(self, docker_ip):
        self.docker_ip = docker_ip
        self.start()

    def start(self):
        threading.Thread(target=self.monitor).start()

    def monitor(self):
        pcap = sniff(iface='docker0', timeout=900, filter='port not 22')
        self.parse(pcap)

    def parse(self, pcap):
        tcp_sessions = pcap[TCP].sessions()
        dns_sessions = pcap[DNS].sessions()
        for key, pkts in tcp_sessions.items():
            timelist = [pkt.time for pkt in pkts]
            if self.check(timelist):
                src = key.split()[1]
                dst = key.split()[-1]
                server = src if IPY(src.split(':')[0]).iptype() == 'PUBLIC' else dst
                self.save_to_mongo(server)
        dnstimelist = [pkt[0].time for key, pkt in dns_sessions.items()]
        if self.check(dnstimelist):
            server = self.parse_dns(pcap[DNS])
            self.save_to_mongo(server)

    def check(self, timelist):
        N = len(timelist)
        if N == 0:
            return None
        S = sum(timelist)
        min = timelist[0]
        max = timelist[-1]
        try:
            d = (max - min)/(N - 1)
        except ZeroDivisionError:
            return None
        airsum = N * (min + max)/2
        return True if -2 < airsum-S < 2 else None

    def parse_dns(self, pcaps):
        ans = {}; qry = {};
        for pcap in pcaps:
            if pcap.qr:
                if pcap.ancount > 0 and isinstance(pcap.an, DNSRR):
                    name = pcap.an.rdata
                    if name not in ans.keys():
                        ans[name] = 0
                    ans[name] += 1
            else:
                if pcap.qdcount > 0 and isinstance(pcap.qd, DNSQR):
                    name = pcap.qd.qname
                    if name not in qry.keys():
                        qry[name] = 0
                    qry[name] += 1
        return sorted(ans.keys())[-1], sorted(qry.keys())[-1]

    def save_to_mongo(self, server):
        if isinstance(server, tuple):
            result = {'C2domain': server}
        else:
            result = {'C2ip': server}
        try:
            if mongodb[MONGO_TABLE1].find_one_and_update(
                {'docker_ip': self.docker_ip, 'flag': 1}, {'$set': result}):
                print 'save to mongo successd'
        except Exception:
            print 'save to mongo errorrrr'


