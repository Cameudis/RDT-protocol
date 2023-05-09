"""
gbn.py
~~~~~~
This module implements the sender and receiver of Go-Back-N Protocol.

:copyright: (c) 2018 by ZiHuan Wang.
:date: 2019/10/29
"""
import random
import socket
import struct
import time

# constants
BUFFER_SIZE = 4096
TIMEOUT = 3
WINDOW_SIZE = 3
LOSS_RATE = 0.1

# FLAG
SYN = 1
FIN = 2


def getChecksum(data):
    """
    char_checksum 按字节计算校验和。每个字节被翻译为无符号整数
    @param data: 字节串
    """
    length = len(str(data))
    checksum = 0
    for i in range(0, length):
        checksum += int.from_bytes(bytes(str(data)[i], encoding='utf-8'), byteorder='little', signed=False)
        checksum &= 0xFF  # 强制截断

    return checksum


def analyse_pkt(pkt):
    if len(pkt) < 4:
        print('Invalid Packet')
        return False
    seqNum = pkt[0]
    ackNum = pkt[1]
    flag = pkt[2]
    checksum = pkt[3]
    data = pkt[4:]

    print("[Recv] SEQ =", seqNum, ", ACK =", ackNum, end=' ')
    if flag == SYN:
        print("(SYN)")
    elif flag == FIN:
        print("(FIN)")
    else:
        print("")

    return seqNum, ackNum, flag, checksum, data


def make_pkt(seqNum, ackNum, data, start=False, stop=False):
    assert(not(start and stop))
    flag = 0
    flag = SYN if start else flag
    flag = FIN if stop else flag
    return struct.pack('BBBB', seqNum, ackNum, flag, getChecksum(data)) + data


class GBNSender:
    def __init__(self, senderSocket, address, timeout=TIMEOUT,
                    windowSize=WINDOW_SIZE, lossRate=LOSS_RATE):
        self.sender_socket = senderSocket
        self.timeout = timeout
        self.address = address
        self.window_size = windowSize
        self.loss_rate = lossRate
        self.send_base = 0
        self.next_seq = 0
        self.packets = [None] * 256
        self.connected = False

    def connect(self):
        if (self.connected):
            print(f"[error] You have connected to addr {self.address}")
            return

        # randomize init seq
        self.send_base = random.randint(0, 256)
        self.next_seq = self.send_base + 1

        syn_pack = make_pkt(self.send_base, 0, b"", start=True)
        self.udp_send(syn_pack)

        self.sender_socket.settimeout(self.timeout)
        while True:
            try:
                data, address = self.sender_socket.recvfrom(BUFFER_SIZE)
                seqNum, ackNum, flag, checksum, data = analyse_pkt(data)
                if flag == SYN:
                    print(f"Connected to {self.address}")
                    break

            except socket.timeout:
                print("[timeout] SYN ACK")
                self.udp_send(syn_pack)

        self.connected = True

    def udp_send(self, pkt):
        if self.loss_rate == 0 or random.randint(0, int(1 / self.loss_rate)) != 1:
            self.sender_socket.sendto(pkt, self.address)
        else:
            print('[Send] Packet lost.')
        time.sleep(0.2)

    def wait_ack(self):
        if (not self.connected):
            print("[error] not connected")

        self.sender_socket.settimeout(self.timeout)
        timeout_count = 0

        while True:
            if timeout_count >= 10:
                # 连续超时10次，接收方已断开，终止
                break
            try:
                data, address = self.sender_socket.recvfrom(BUFFER_SIZE)
                seqNum, ackNum, flag, checksum, data = analyse_pkt(data)

                if ackNum < self.send_base and 256 + ackNum - self.send_base < 10:
                    self.send_base = ackNum
                else:
                    self.send_base = max(self.send_base, ackNum)
                
                if self.send_base == self.next_seq:  # 已发送分组确认完毕
                    self.sender_socket.settimeout(None)
                    return True

            except socket.timeout:
                # 超时，重发分组. GBN
                print('[timeout] ACK')

                i = self.send_base
                while i != self.next_seq:
                    print('Sender resend packet:', i)
                    self.udp_send(self.packets[i])
                    i = (i + 1) % 256

                self.sender_socket.settimeout(self.timeout)  # reset timer
                timeout_count += 1

        return False




class GBNReceiver:
    def __init__(self, receiverSocket, timeout=10, lossRate=0):
        self.receiver_socket = receiverSocket
        self.timeout = timeout
        self.loss_rate = lossRate
        self.expect_seq = 0
        self.target = None
        self.connected = False

    def listen(self):
        while True:
            try:
                data, address = self.receiver_socket.recvfrom(BUFFER_SIZE)
            except InterruptedError:
                assert(0)

            seqNum, ackNum, flag, checksum, data = analyse_pkt(data)
            if flag == SYN:
                print("SYN Received")
                self.target = address
                self.expect_seq = seqNum + 1
                self.connected = True

                # send SYN ACK
                pkg = make_pkt(0, self.expect_seq, b"", start=True)
                self.udp_send(pkg)

                return

    def udp_send(self, pkt):
        if self.loss_rate == 0 or random.randint(0, 1 / self.loss_rate) != 1:
            self.receiver_socket.sendto(pkt, self.target)
            print('[Send] send ACK:', pkt[1])
        else:
            print('[Send] send ACK:', pkt[1], ', but lost.')

    def wait_data(self):
        """
        接收方等待接受数据包
        """
        self.receiver_socket.settimeout(self.timeout)

        while True:
            try:
                data, address = self.receiver_socket.recvfrom(BUFFER_SIZE)
                seqNum, ackNum, flag, checksum, data = analyse_pkt(data)

                # 收到期望数据包且未出错
                if seqNum == self.expect_seq and getChecksum(data) == checksum:
                    self.expect_seq = (self.expect_seq + 1) % 256
                    ack_pkt = make_pkt(0, self.expect_seq, b"")
                    self.udp_send(ack_pkt)
                    if flag & FIN:    # 最后一个数据包
                        return data, True
                    else:
                        return data, False
                else:
                    ack_pkt = make_pkt(0, self.expect_seq, b"")
                    self.udp_send(ack_pkt)
                    return bytes('', encoding='utf-8'), False

            except socket.timeout:
                return bytes('', encoding='utf-8'), False

