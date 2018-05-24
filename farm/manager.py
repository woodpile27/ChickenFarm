import time
import docker
import threading
import subprocess
from capture import FileCapture, DDosMonitor, C2Monitor
from config import *


class Management(object):

    def __init__(self, tcpServer):
        self.client = docker.from_env()
        self.tcpServer = tcpServer
        self.docker_ip ,self.docker_iface = self.create()
        self.evt = threading.Event()
        self.file_capture = FileCapture('Wetland 1', self.docker_ip, self.evt)
        self.docker_count = 1
        self.flow_port = 9995

    def start(self):
        self.thread_start(self.file_capture.sniff_file)
        self.thread_start(self.file_capture.get_from_redis)
        self.thread_start(self.monitor)

    def monitor(self):
        while True:
            if self.evt.isSet():
                self.evt.clear()
                time.sleep(50)
                self.change()

    def create(self):
        contain = self.client.containers.run(IMAGE_NAME, cpu_quota=10000, \
                  cpu_period=20000, mem_limit='512m', detach=True)
        contain = self.client.containers.get(contain.id)
        docker_ip = contain.attrs['NetworkSettings']['IPAddress']
        docker_iface = self.interface(contain.attrs['NetworkSettings']['SandboxKey'])
        self.tcpServer.cfg.set("wetland", "docker_addr", docker_ip)
        return docker_ip, docker_iface

    def guard(self):
        subprocess.call("fprobe -i %s 127.0.0.1:%d" % (self.docker_iface,self.flow_port), shell=True)
        locals()['guard'+str(self.docker_count)] = DDosMonitor(self.flow_port,self.docker_ip)
        locals()['C2'+str(self.docker_count)] = C2Monitor(self.docker_ip)
        self.flow_port += 1

    def change(self):
        self.guard()
        self.docker_count += 1
        new_name = 'Wetland ' + str(self.docker_count)
        self.docker_ip, self.docker_iface = self.create()
        self.tcpServer.change_docker(self.docker_ip)
        self.file_capture.change_docker(new_name, self.docker_ip)

    def interface(self, sandboxkey):
        peer_ifindex = subprocess.check_output('nsenter --net=%s ethtool -S eth0 |grep peer_ifindex' \
                       % sandboxkey, shell=True).split()[-1]
        iface = subprocess.check_output('ip link | grep "^%s: veth"' % peer_ifindex \
                                         ,shell=True).split()[1].split('@')[0]
        return iface

    def thread_start(self, target, *args):
        thread = threading.Thread(target=target, args=args)
        thread.setDaemon(True)
        thread.start()
