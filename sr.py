import random
import socket
import struct
import time

# constants
HEADER_SIZE = 4
BUFFER_SIZE = 4096
TIMEOUT = 3
BASIC_TIMEOUT = 0.5
WINDOW_SIZE = 3
LOSS_RATE = 0.2
MAX_TIMEOUT = 10

# FLAG
SYN = 1
FIN = 2
ACK = 4

def getChecksum(data):
    length = len(str(data))
    checksum = 0
    for i in range(0, length):
        checksum += int.from_bytes(bytes(str(data)[i], encoding='utf-8'), byteorder='little', signed=False)
        checksum &= 0xFF
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
    if flag & SYN:
        print("(SYN)", end='')
    if flag & FIN:
        print("(FIN)", end='')
    if flag & ACK:
        print("(ACK)", end='')
    print()

    return seqNum, ackNum, flag, checksum, data

def make_pkt(seqNum, ackNum, data, start=False, stop=False, ack=False):
    assert(not(start and stop))
    flag = 0
    flag |= SYN if start else 0
    flag |= FIN if stop else 0
    flag |= ACK if ack else 0
    return struct.pack('BBBB', seqNum, ackNum, flag, getChecksum(data)) + data


class SRSocket:
    def __init__(self, timeout=TIMEOUT,
                    windowSize=WINDOW_SIZE, lossRate=LOSS_RATE):
        # socket config
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.timeout = timeout
        self.window_size = windowSize
        self.address = None
        self.loss_rate = lossRate

        # connection
        self.connected = False
        self.is_server = False

        # send
        self.sdata = [None] * 256   # send data
        self.spos = 0               # send position (last available packet + 1)
        self.sbase = 0              # send base
        self.snext = 0              # send next seq number

        self.sclkq = []             # send clock queue (seq:timestamp)

        # congestion control
        self.ackcount = 0

        # receive
        self.rdata = [None] * 256   # receive data
        self.rbase = 0              # receive base (not return yet)
        self.rexpect = 0            # receive expect


    def udp_send(self, pkt):
        if self.loss_rate == 0 or random.randint(0, int(1 / self.loss_rate)) != 1:
            self.udp_socket.sendto(pkt, self.address)
            print('[Send] SEQ =', pkt[0], ', ACK =', pkt[1], end=' ')
            if pkt[2] & SYN:
                print('(SYN)', end='')
            if pkt[2] & FIN:
                print('(FIN)', end='')
            if pkt[2] & ACK:
                print('(ACK)', end='')
            print()
        else:
            print('[Send] Packet lost.')
        time.sleep(0.01)


    def connect(self, address):
        if (self.connected):
            print(f"[error] You have connected to addr {self.address}")
            return

        # randomize init seq
        self.sbase = random.randint(0, 255)
        self.snext = self.sbase
        self.spos  = self.sbase

        self.address = address
        syn_pack = make_pkt((self.sbase-1)%256, 0, b"", start=True)
        self.udp_send(syn_pack)

        self.udp_socket.settimeout(self.timeout)
        while True:
            try:
                rcvpkt = self.udp_socket.recv(HEADER_SIZE+BUFFER_SIZE)
                seqNum, ackNum, flag, checksum, data = analyse_pkt(rcvpkt)
                if (flag & SYN) and (flag & ACK) and (ackNum == self.sbase):
                    self.connected = True
                    self.rbase = (seqNum + 1) % 256
                    self.rexpect = self.rbase
                    break

            except socket.timeout:
                print("[timeout] SYN ACK")
                self.udp_send(syn_pack)


    def send(self, data):
        if (not self.connected):
            print("[error] not connected")
            return
        
        if data == b'':
            self.sdata[self.spos] = data
            self.spos = (self.spos + 1) % 256
        else:
            # parse data into packets
            data = [data[i:i+BUFFER_SIZE] for i in range(0, len(data), BUFFER_SIZE)]
            if len(data) >= 256/2:
                print("[error] data too large")
                return
            for i in range(len(data)):
                self.sdata[self.spos] = data[i]
                self.spos = (self.spos + 1) % 256
        
        # send packets
        while self.sbase != self.spos:
            if (self.snext - self.sbase) % 256 < self.window_size and self.snext != self.spos:
                pkt = make_pkt(self.snext, self.rexpect, self.sdata[self.snext])
                self.udp_send(pkt)
                self.sclkq.append((self.snext, time.time()))    # add to clock queue
                self.snext = (self.snext + 1) % 256
            else:
                if not self._wait():
                    return


    def _wait(self, recv=False):
        if (not self.connected):
            print("[error] not connected")

        self.udp_socket.settimeout(BASIC_TIMEOUT)
        timeout_count = 0

        while True:
            if timeout_count >= MAX_TIMEOUT:
                print("[ERROR] connection lost (timeout)")
                break
            try:
                rcvpkt = self.udp_socket.recv(HEADER_SIZE+BUFFER_SIZE)
                seqNum, ackNum, flag, checksum, data = analyse_pkt(rcvpkt)
                timeout_count = 0
            
                if (flag & SYN):
                    synack_pack = make_pkt(self.snext, self.rexpect, b"", start=True, ack=True)
                    self.udp_send(synack_pack)
                    continue

                # handle ACK
                if (flag & ACK):
                    # update clock queue
                    crt_min_unacked = self.snext
                    i = 0
                    while i < len(self.sclkq):
                        crt = self.sclkq[i][0]
                        if ackNum == crt:
                            self.sclkq.pop(i)
                        else:
                            if (crt - self.sbase) % 256 < (self.snext - self.sbase) % 256:  # in window
                                if crt < WINDOW_SIZE:
                                    crt += 256
                                if crt < crt_min_unacked:
                                    crt_min_unacked = crt
                            i += 1
                    crt_min_unacked %= 256
                    
                    if self.sbase != crt_min_unacked:
                        # update window size (congestion control)
                        self.ackcount += (crt_min_unacked - self.sbase) % 256
                        if self.ackcount >= self.window_size:
                            print('[CNG_CTRL] add window size from', self.window_size, 'to', self.window_size+1)
                            self.window_size += 1
                            self.ackcount = 0

                        self.sbase = crt_min_unacked
                        self.udp_socket.settimeout(None)
                        return True
                    else:
                        continue

                # handle FIN
                if (flag & FIN):
                    ack_pkt = make_pkt((self.snext-1)%256, self.rexpect, b"", ack=True, stop=True)
                    self.udp_send(ack_pkt)
                    self.udp_socket.settimeout(None)
                    self.connected = False
                    return False
                
                # save data
                if getChecksum(data) == checksum:
                    if self.rdata[seqNum] is None:
                        # print('[Debug] Fill data at', seqNum, 'with', len(data))
                        self.rdata[seqNum] = data

                    # send ACK
                    ack_pkt = make_pkt((self.snext-1)%256, seqNum, b"", ack=True)
                    self.udp_send(ack_pkt)

                    # update rexpect
                    i = self.rexpect
                    while not self.rdata[i] is None:
                        self.rexpect = (self.rexpect + 1) % 256
                        i = self.rexpect

            except socket.timeout:
                if (recv):
                    return True

                # check clock queue
                while len(self.sclkq) > 0:
                    if time.time() - self.sclkq[0][1] >= self.timeout:
                        pkt = make_pkt(self.sclkq[0][0], self.rexpect, self.sdata[self.sclkq[0][0]])
                        self.udp_send(pkt)
                        self.sclkq.append((self.sclkq[0][0], time.time()))
                        del self.sclkq[0]

                        # update window size (congestion control)
                        new_window_size = max(2, self.window_size // 2)
                        print('[CNG_CTRL] reduce window size from', self.window_size, 'to', new_window_size)
                        self.window_size = new_window_size
                    else:
                        break

        return False


    def recv(self, size=BUFFER_SIZE):
        timeout_count = 0
        while self.rbase == self.rexpect:
            if (not self.connected):
                return b""
            if timeout_count >= 50:
                raise Exception("[ERROR] connection lost (timeout)")
            self._wait(recv=True)
            timeout_count += 1
        
        data = self.rdata[self.rbase]
        self.rdata[self.rbase] = None
        self.rbase = (self.rbase + 1) % 256
        return data[:size]

    
    def close(self):
        if (not self.connected):
            print("[info] FIN...")
            return

        # send FIN
        fin_pack = make_pkt(self.snext, self.rexpect, b"", stop=True)
        self.udp_send(fin_pack)

        # wait for FIN ACK
        self.udp_socket.settimeout(self.timeout)
        timeout_count = 0
        while True:
            if timeout_count >= 3:
                self.connected = False
                print("[info] FIN...")
                break
            try:
                rcvpkt = self.udp_socket.recv(HEADER_SIZE+BUFFER_SIZE)
                seqNum, ackNum, flag, checksum, data = analyse_pkt(rcvpkt)
                if flag & FIN and flag & ACK:
                    self.connected = False
                    print("[info] FIN...")
                    break

            except socket.timeout:
                timeout_count += 1
                print("[timeout] FIN ACK")
                self.udp_send(fin_pack)


    def bind(self, address):
        self.address = address
        self.udp_socket.bind(address)


    def listen(self):
        if (self.connected):
            print(f"[error] You have connected to addr {self.address}")
            return
        self.is_server = True
    

    def accept(self):
        if (not self.is_server):
            print("[error] not server")
            return

        self.udp_socket.settimeout(None)
        rcvpkt, address = self.udp_socket.recvfrom(HEADER_SIZE+BUFFER_SIZE)
        seqNum, ackNum, flag, checksum, data = analyse_pkt(rcvpkt)
        if flag & SYN:
            print("[info] SYN from", address)
            self.connected = True
            self.address = address
            self.rbase = (seqNum + 1) % 256
            self.rexpect = self.rbase
            self.sbase = random.randint(0, 255)
            self.snext = self.sbase
            self.spos  = self.sbase

            synack_pack = make_pkt((self.sbase-1)%256, self.rexpect, b"", start=True, ack=True)
            self.udp_send(synack_pack)
        else:
            print("[error] not SYN")
            return
