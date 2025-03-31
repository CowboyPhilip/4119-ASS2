# 
# Columbia University - CSEE 4119 Computer Networks
# Assignment 2 - Mini Reliable Transport Protocol
#
# mrt_client.py - defining client APIs of the mini reliable transport protocol
#

import socket
import threading
import time
import random
import json
import hashlib
from datetime import datetime
import base64
import queue

class Client:
    def init(self, src_port, dst_addr, dst_port, segment_size):
        """
        initialize the client and create the client UDP channel

        arguments:
        src_port -- the port the client is using to send segments
        dst_addr -- the address of the server/network simulator
        dst_port -- the port of the server/network simulator
        segment_size -- the maximum size of a segment (including the header)
        """

        self.src_port = src_port
        self.dst_addr = dst_addr
        self.dst_port = dst_port
        self.segment_size = segment_size
        self.payload_size = segment_size - 200
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('127.0.0.1', src_port))
        self.sock.settimeout(0.5)

        self.base = 0
        self.next_seq = 0
        self.window_size = 5  # 可调的发送窗口
        self.timeout = 1.0

        self.send_lock = threading.Lock()
        self.ack_event = threading.Event()
        self.unacked_packets = {}
        self.running = True

        self.send_thread = None
        self.ack_thread = None

        self.third_handshaked = False

        self.log_file = open(f"log_{self.src_port}.txt", "w")
        # self.expected_packets = 0
        self.send_queue = queue.Queue()


    def checksum(self, data):
        return hashlib.md5(data.encode() if isinstance(data, str) else data).hexdigest()
    
    def make_packet(self, pkt_type, seq, ack, payload=""):
        # return a dict
        # payload应该是base64编码的bytes 或 空 （SYN.ACK时）
        if isinstance(payload,bytes):
            payload = base64.b64encode(payload).decode('ascii')
        packet = {
            "type": pkt_type,
            "seq": seq,
            "ack": ack,
            "payload": payload,
            "checksum": self.checksum(payload)
        }
        return packet
    
    # def timeout(self):
    #     print("[Client] Timeout! Resending window...")
    #     self.ack_event.set()  # Unblock waiting thread to retransmit

    # def recv_packet(self):
    #     try:
    #         data = self.sock.recv(4096)
    #         packet = json.loads(data.decode())
    #         payload = packet.get("payload", "")
    #         if packet.get("checksum") != self.checksum(payload):
    #             print(f"[Client] Checksum mismatch for packet {packet.get('seq')}, discarded")
    #             return None
    #         return packet
    #     except socket.timeout:
    #         return None
    #     except Exception as e:
    #         print(f"[Client] Failed to parse packet: {e}")
    #         return None
        
    def connect(self):
        """
        connect to the server
        blocking until the connection is established

        it should support protection against segment loss/corruption/reordering 
        """
        print("[Client] Trying to connect to server")
        syn_pkt = self.make_packet("syn", 0, 0)
        # syn_pkt = json.dumps(syn_pkt).encode()
        self.third_handshaked = False
        while True:
            print("sending syn")
            self.sock.sendto(json.dumps(syn_pkt).encode(), (self.dst_addr, self.dst_port))
            self.log(self.dst_port, self.src_port, syn_pkt["seq"], syn_pkt["ack"], syn_pkt["type"].upper(), len(syn_pkt["payload"]))
            try:
                raw, _ = self.sock.recvfrom(65536)
                print("[Client] recv syn-ack maybe",raw)
                pkt = json.loads(raw.decode())
                if pkt["type"] == "syn-ack":
                    print("[Client] recv syn-ack")
                    self.log(self.dst_port, self.src_port, pkt["seq"], pkt["ack"], pkt["type"].upper(), len(pkt["payload"]))
                    ack_pkt = self.make_packet("ack", 0, pkt["ack"] + 1)
                    self.sock.sendto(json.dumps(ack_pkt).encode(), (self.dst_addr, self.dst_port))
                    self.log(self.dst_port, self.src_port, ack_pkt["seq"], ack_pkt["ack"], ack_pkt["type"].upper(), len(ack_pkt["payload"]))
                    print("[Client] Sent ACK, connection established")
                    self.ack_thread = threading.Thread(target=self.ack_listener)
                    self.ack_thread.start()
                    self.send_thread = threading.Thread(target=self.send_loop)
                    self.send_thread.start()


                    return
            except socket.timeout:
                print("[Client] Connect Time Out, CONTINUE")
                continue
            except Exception as e:
                print("[Client] ", e)
                continue

    def parse_ack(self,raw):
        expected_fields = ["type","seq","ack","payload"]
        expected_types = ["syn-ack","ack","fin"]
        try:
            pkt = json.loads(raw.decode())
            # pkt = json.loads(pkt_str)
            
            # 检查字段完整性
            if expected_fields:
                for field in expected_fields:
                    if field not in pkt:
                        print(f"[Client] packet drop, error: missing field: {field}")
                        return None
            if pkt["type"] not in expected_types:
                print("[Client] packet drop, error: unknown types")
                return None
            if pkt["payload"] != "":
                print("[Client] packet drop, error: payload corrupted")
                return None
            return pkt

        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            print(f"[Client] packet drop, error: {e}")
            return None
        except Exception as e:
            print(f"[Client] General parse/validation error: {e}")
            return None

    def ack_listener(self):
        """
        后台监听 ack 以及fin，滑动窗口
        """
        while self.running:
            try:
                raw, _ = self.sock.recvfrom(65536)
                pkt = self.parse_ack(raw)

                if pkt == None:
                    continue
                if pkt["type"] == "ack":
                    ack_num = pkt["ack"]
                    print(f"[Client] acking seq number {ack_num}")
                    print("[Client] recv pkt", pkt)
                    self.log(self.dst_port, self.src_port, pkt["seq"], pkt["ack"], pkt["type"].upper(), len(pkt["payload"]))
                    with self.send_lock:
                        keys = list(self.unacked_packets.keys())
                        for k in keys:
                            if k <= ack_num:
                                self.unacked_packets.pop(k)
                        self.base = ack_num + 1
                        self.ack_event.set()
                    self.third_handshaked = True
                elif pkt["type"] == "fin":
                    print("[Client] server want to close connection")
                    self.log(self.dst_port, self.src_port, pkt["seq"], pkt["ack"], pkt["type"].upper(), len(pkt["payload"]))
                    pkt = {
                        "type":"fin-ack",
                        "seq":0,
                        "ack":0,
                        "payload":""
                    }
                    for _ in range(5):
                        self.sock.sendto(json.dumps(pkt).encode(), (self.dst_addr, self.dst_port))
                        self.log(self.src_port, self.dst_port, pkt["seq"], pkt["ack"], pkt["type"].upper(), len(pkt["payload"]))
                    self.running = False
                    # print("[Client] closed")
            except socket.timeout:
                continue

    # def send(self, data):
    #     """
    #     send a chunk of data of arbitrary size to the server
    #     blocking until all data is sent

    #     it should support protection against segment loss/corruption/reordering and flow control

    #     arguments:
    #     data -- the bytes to be sent to the server
    #     """
    #     print("[Client] start sending data")
    #     if isinstance(data, bytes):
    #         pass
    #     else:
    #         raise "data format error, should be bytes"
    #     # data_str = data.decode() if isinstance(data, bytes) else data
    #     # segments = [data_str[i:i+self.segment_size] for i in range(0, len(data_str), self.segment_size)]

    #     # list of payload segments, each
    #     payloads = [data[i:i+self.payload_size] for i in range(0, len(data), self.payload_size)]
    #     start = time.time()
    #     self.expected_packets += len(payloads)
    #     while self.base < self.expected_packets and self.running:
    #         # 如果一个对data的ack没收到 说明ack丢失了 重新connect
    #         # if self.third_handshaked==False and time.time() - start > 2:
    #         #     self.connect()
    #         #     self.base = 0
    #         #     self.next_seq = 0
    #         #     self.unacked_packets.clear()
    #         #     return

    #         with self.send_lock:
    #             while self.next_seq < self.base + self.window_size and self.next_seq < self.expected_packets:
    #                 pkt = self.make_packet("data", self.next_seq, 0, payloads[self.next_seq])
    #                 self.unacked_packets[self.next_seq] = {"packet": pkt, "time": time.time()}
    #                 print("[Client] sending data", pkt)
    #                 self.sock.sendto(json.dumps(pkt).encode(), (self.dst_addr, self.dst_port))
    #                 self.log(self.src_port, self.dst_port, pkt["seq"], pkt["ack"], pkt["type"].upper(), len(payloads[self.next_seq]))
    #                 self.next_seq += 1

    #         # 检查超时重传
    #         time.sleep(0.1)
    #         now = time.time()
    #         with self.send_lock:
    #             for seq, info in self.unacked_packets.items():
    #                 if now - info["time"] > self.timeout:
    #                     print(f"[Client] Timeout, retransmitting seq={seq}")
    #                     self.sock.sendto(json.dumps(info["packet"]).encode(), (self.dst_addr, self.dst_port))
    #                     self.unacked_packets[seq]["time"] = now
    #     # while self.running:
    #     #     time.sleep(0.5)
    #     print("[Client] All data sent and acknowledged")
    #     return len(data)

    def send_loop(self):
        while self.running:
            with self.send_lock:
                # 填充窗口：只要窗口有空位 && 还有要发的数据
                while self.next_seq < self.base + self.window_size and not self.send_queue.empty():
                    payload = self.send_queue.get()
                    pkt = self.make_packet("data", self.next_seq, 0, payload)
                    self.unacked_packets[self.next_seq] = {"packet": pkt, "time": time.time()}
                    self.sock.sendto(json.dumps(pkt).encode(), (self.dst_addr, self.dst_port))
                    self.log(self.src_port, self.dst_port, pkt["seq"], pkt["ack"], pkt["type"].upper(), len(payload))
                    print(f"[Client] Sent seq={self.next_seq}")
                    self.next_seq += 1

                # 重传超时包
                now = time.time()
                for seq, info in self.unacked_packets.items():
                    if now - info["time"] > self.timeout:
                        print(f"[Client] Timeout, retransmitting seq={seq}")
                        self.sock.sendto(json.dumps(info["packet"]).encode(), (self.dst_addr, self.dst_port))
                        self.unacked_packets[seq]["time"] = now
            time.sleep(0.05)

    def send(self, data):
        if not isinstance(data, bytes):
            raise ValueError("data must be bytes")

        payloads = [data[i:i+self.payload_size] for i in range(0, len(data), self.payload_size)]
        total_segs = len(payloads)

        with self.send_lock:
            start_seq = self.next_seq + self.send_queue.qsize()  # 预计发送的起始 seq
            for payload in payloads:
                self.send_queue.put(payload)

        # 阻塞等待所有这些数据都被 ack 掉
        while True:
            with self.send_lock:
                acked_upto = self.base
            if acked_upto >= start_seq + total_segs:
                break
            time.sleep(0.1)

        return len(data)
    
    def close(self):
        """
        request to close the connection with the server
        blocking until the connection is closed
        """
        while self.running:
            time.sleep(0.1)
        # self.running = False
        print("[Client] closing connection...")
        self.ack_thread.join()
        while True:
            try:
                raw, addr = self.sock.recvfrom(65536)
                end = self.parse_ack(raw)
                if end == None:
                    continue
                if end["type"]=="ack":
                    print("[Client] recv ACK, close")
                    self.sock.close()
                    self.log_file.close()
                    return 
            except socket.timeout:
                continue
            except Exception as e:
                print(f"[Client] close fail, error: {e}")


    def log(self, src_port, dst_port, seq, ack, pkt_type, payload_length):
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        line = f"{now} {src_port} {dst_port} {seq} {ack} {pkt_type} {payload_length}\n"
        self.log_file.write(line)
        self.log_file.flush()


# python3 app_client.py 50000 127.0.0.1 51000 1460