# 
# Columbia University - CSEE 4119 Computer Networks
# Assignment 2 - Mini Reliable Transport Protocol
#
# mrt_server.py - defining server APIs of the mini reliable transport protocol
#

import socket
import threading
import time
import random
import json
import hashlib
from datetime import datetime
import base64

# Server
#
class Server:
    def init(self, src_port, receive_buffer_size):
        """
        initialize the server, create the UDP connection, and configure the receive buffer

        arguments:
        src_port -- the port the server is using to receive segments
        receive_buffer_size -- the maximum size of the receive buffer
        """
        self.src_port = src_port
        self.receive_buffer_size = receive_buffer_size
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('127.0.0.1', src_port))
        self.sock.settimeout(0.5)
        self.expected_seq = 0
        self.client_addr = None
        self.buffer = {}
        self.recv_data = bytearray()
        self.lock = threading.Lock()
        self.closed = False
        self.recv_thread = None
        self.conn_established = threading.Event()

        self.log_file = open(f"log_{self.src_port}_server.txt", "w")
        
    def checksum(self, data):
        return hashlib.md5(data.encode() if isinstance(data, str) else data).hexdigest()

    # def valid_packet(self, pkt):
    #     return pkt["checksum"] == self.checksum(pkt["payload"])
    
    def parse_packet(self,raw):
        """
        解析并校验一个 UDP 包。出错返回 None。
        expected_fields 是必须存在的字段列表。
        """
        expected_fields = ["type","seq","ack","payload","checksum"]
        expected_types = ["syn","syn-ack","ack","fin","fin-ack","data"]
        try:
            pkt = json.loads(raw.decode())
            # pkt = json.loads(pkt_str)
            
            # 检查字段完整性
            if expected_fields:
                for field in expected_fields:
                    if field not in pkt:
                        print(f"[Server] packet drop, error: missing field: {field}")
                        return None
            
            if pkt["type"] not in expected_types:
                print("[Server] packet drop, error: type unknown")
                return None
            # 校验 checksum
            payload = pkt["payload"]
            # computed_checksum = hashlib.md5(payload.encode() if isinstance(payload, str) else payload).hexdigest()
            if pkt.get("checksum") != self.checksum(payload):
                print("[Server] packet drop, error: checksum mismatch")
                return pkt["type"]
            if pkt["payload"] != "":
                pkt["payload"] = base64.b64decode(payload)
            return pkt

        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            print(f"[Server] packet drop, error: {e}")
            return None
        except Exception as e:
            print(f"[Server] General parse/validation error: {e}")
            return None
        
    def send_ack(self, ack_num, type="ack"):
        ack_pkt = {
            "type": type,
            "seq": 0,
            "ack": ack_num,
            "payload": "",
            "checksum": self.checksum("")
        }
        self.sock.sendto(json.dumps(ack_pkt).encode(), self.client_addr)
        self.log(self.src_port, self.client_addr[1], ack_pkt["seq"], ack_pkt["ack"], ack_pkt["type"].upper(), len(ack_pkt["payload"]))
    
    def accept(self):
        """
        accept a client request
        blocking until a client is accepted

        it should support protection against segment loss/corruption/reordering 

        return:
        the connection to the client 
        """
        # conn = None
        # return conn
        print("[Server] Waiting for connection...")
        # print("Waiting for client...")
        while not self.conn_established.is_set():
            try:
                raw, addr = self.sock.recvfrom(65536)
                print("[Server] recv", raw)
                pkt = self.parse_packet(raw)
                if pkt==None or isinstance(pkt, str):
                    continue
                seq = pkt["seq"]
                if pkt["type"] == "syn":
                    print("[Server] recv syn")
                    self.client_addr = addr
                    self.log(self.client_addr[1], self.src_port, pkt["seq"], pkt["ack"], pkt["type"].upper(), len(pkt["payload"]))
                    self.send_ack(seq + 1,"syn-ack")
                    print(f"[Server] send syn-ack ")

                    # while True:
                    start = time.time()
                    while time.time()-start < 2:   # 开始等待client的ACK 2s后重启 应对syn-ack和ack的丢失
                        print("[Server] waiting for ACK")
                        try:
                            raw, addr = self.sock.recvfrom(65536)
                            print("[Server] recv ack from client maybe")
                            ack_pkt = self.parse_packet(raw)
                            if ack_pkt == None:
                                continue
                            if (ack_pkt["type"] == "ack" and ack_pkt["ack"] == seq+2) or (ack_pkt["type"]=="data"):
                                self.conn_established.set()
                                self.recv_thread = threading.Thread(target=self.receive_loop)
                                self.recv_thread.start()
                                print("[Server] Connection established with", addr)
                                self.log(self.client_addr[1],self.src_port, ack_pkt["seq"], ack_pkt["ack"], ack_pkt["type"].upper(), len(ack_pkt["payload"]))
                                return addr
                        except socket.timeout:
                            break
                    
                    # self.conn_established.set()
                    # self.recv_thread = threading.Thread(target=self.receive_loop)
                    # self.recv_thread.start()
                    # return addr
            except socket.timeout:
                print("[Server] accept time out")
                continue
            # except Exception
            except Exception as e:
                print(e)
                continue
            # time.sleep(0.1)
        return None

    def receive_loop(self):
        """
        后台持续接收数据包并校验、缓存在 buffer 中
        """
        while not self.closed:
            try:
                raw, addr = self.sock.recvfrom(65536)
                pkt = self.parse_packet(raw)
                if pkt == None or isinstance(pkt, str):
                    # print("[Server] invalid json, continue")
                    continue
                self.log(self.client_addr[1], self.src_port, pkt["seq"], pkt["ack"], pkt["type"].upper(), len(pkt["payload"]))
                if pkt["type"]!="data":
                    print(f"[Server] packet drop, error: unknown pakcet type {pkt['type']}")
                    continue # 接收到了connect/accept期间尚未到达的control pkt
                
                seq = pkt["seq"]
                print(f"[Server] recv seq {seq}")
                payload = pkt["payload"]

                with self.lock:
                    if seq == self.expected_seq:
                        self.recv_data.extend(payload)
                        self.expected_seq += 1
                        self.send_ack(seq)
                        # 处理 buffer 中乱序的数据
                        while self.expected_seq in self.buffer:
                            self.recv_data.extend(self.buffer.pop(self.expected_seq))
                            self.send_ack(self.expected_seq)
                            self.expected_seq += 1
                    elif seq > self.expected_seq:
                        # buffer未满，存储乱序包
                        if len(self.buffer) < self.receive_buffer_size:
                            self.buffer[seq] = payload
                        self.send_ack(self.expected_seq - 1)
                    else:
                        # 旧包重传，重发ack
                        self.send_ack(seq)
                # print(f"[Server] recv packet {seq}")
            except socket.timeout:
                continue
            # except Exception as e:
            #     print(f"[Server] Error in receive_loop: {e}")
            

    def receive(self, conn, length):
        """
        receive data from the given client
        blocking until the requested amount of data is received
        
        it should support protection against segment loss/corruption/reordering 
        the client should never overwhelm the server given the receive buffer size

        arguments:
        conn -- the connection to the client
        length -- the number of bytes to receive

        return:
        data -- the bytes received from the client, guaranteed to be in its original order
        """
        # data = b""
        # return data
        while True:
            with self.lock:
                if len(self.recv_data) >= length:
                    result = self.recv_data[:length]
                    self.recv_data = self.recv_data[length:]
                    return bytes(result)
            time.sleep(0.1)


    def close(self):
        """
        close the server and the client if it is still connected
        blocking until the connection is closed
        """
        print("[Server] Closing connection...")
        self.closed = True
        if self.recv_thread:
            self.recv_thread.join()
        
        while True:
            try:
                pkt = {
                    "type":"fin",
                    "seq" :  0,
                    "ack":0,
                    "payload":""
                }
                self.sock.sendto(json.dumps(pkt).encode(), self.client_addr)
                self.log(self.src_port, self.client_addr[1], pkt["seq"], pkt["ack"], pkt["type"].upper(), len(pkt["payload"]))
                

                fin_ack, addr = self.sock.recvfrom(65536)
                fin_ack = json.loads(fin_ack.decode())
                if fin_ack["type"]=="fin-ack":
                    self.log(self.client_addr[1], self.src_port, fin_ack["seq"], fin_ack["ack"], fin_ack["type"].upper(), len(fin_ack["payload"]))
                    self.sock.close()
                    self.log_file.close()
                    print("[Server] Closed")
                    return
            except socket.timeout:
                continue
            except Exception as e:
                print(f"[Server] close fail, error: {e}")


    def log(self, src_port, dst_port, seq, ack, pkt_type, payload_length):
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        line = f"{now} {src_port} {dst_port} {seq} {ack} {pkt_type} {payload_length}\n"
        self.log_file.write(line)
        self.log_file.flush()

# python3 app_server.py 60000 4096