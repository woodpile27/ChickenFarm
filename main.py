import paramiko
from wetland import config
from wetland.server import tcpServer
from farm import manager
from multiprocessing import Process
from threading import Thread

address = config.cfg.get("wetland", "wetland_addr")
port = config.cfg.getint("wetland", "wetland_port")


if __name__ == '__main__':
    tServer = tcpServer.tcp_server((address, port), tcpServer.tcp_handler)
    manager = manager.Management(tServer)
    Thread(target=tServer.serve_forever).start()
    manager.start()
