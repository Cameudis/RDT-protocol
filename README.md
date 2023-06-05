# 可信传输协议实现
#rdt 

在本实验中，我实现了GBN协议、基于连接的全双工可信传输协议，并在此基础上改造了SR协议版本，并为其添加了基础的拥塞控制机制（AIMD）。

主体是gbn.py以及sr.py，API接口模仿socket设计，均能连续通过200轮测试。下面是使用例（这就是全部API了）：

```python
# sr_server.py
from sr import SRSocket

HOST = 'localhost'
PORT = 8000

s = SRSocket()
s.bind((HOST, PORT))

s.listen()
s.accept()
print('Connected by', s.address)

f = open('server/recv.jpg', 'wb')
while True:
    data = s.recv()
    if data == b"": # 空的数据包标识文件结束
        break
    f.write(data)

f.close()
s.send(b"Thank you for your data!")
s.close()
```

```python
# sn_client.py
from sr import SRSocket

HOST = 'localhost'
PORT = 8000

s = SRSocket()
s.connect((HOST, PORT))
print('Connect to', s.address)

f = open('client/data.jpg', 'rb')
data = f.read()
f.close()

s.send(data)  # 阻塞的
s.send(b"")   # 用空的payload表示文件发送结束
print(s.recv().decode())
s.close()
```

客户端将会把图片 `client/data.jpg` 传输至服务器端，服务器保存图片至文件 `server/recv.jpg` 后，将会给客户端发送一条信息，客户端接收并将其打印出来。

由于是全双工的，所以客户端可以给服务器发送消息，服务器也可以给客户端发送消息。

## 1 GBN

### 1.1 准备

为了保证全双工的一致性，从一开始就准备将服务器端协议实现和客户端协议实现放在一个类中，命名为GBNSocket。为了方便起见，我直接模仿socket的api，主要是如下这些函数：

```python
# 客户端
def connect(address)

# 服务端
def bind(address)
def listen()
def accept()

# 通用
def send(data)
def recv([size])
def close()
```

真实的accpet函数会返回一个新的套接字，我将其简化为自身就变成与之通信的套接字。

我设计的数据包结构为：

```c
struct packet {
    uint8_t seqNum;
    uint8_t ackNum; 
    uint8_t flag;
    uint8_t checkSum;
    uint8_t data[];
};
```

其中flag字段有三个有效bit，定义为：

```python
SYN = 1
FIN = 2
ACK = 4
```

而checkSum计算方法非常简单粗暴，就是把所有字节加起来（模加法），如下：

```python
def getChecksum(data):
    length = len(str(data))
    checksum = 0
    for i in range(0, length):
        checksum += int.from_bytes(bytes(str(data)[i], encoding='utf-8'), byteorder='little', signed=False)
        checksum &= 0xFF
    return checksum
```

### 1.2 滑动窗口

我为每个socket维护了两个buffer数组，分别用于发送和接收数据（`sdata` 以及 `rdata`）。
相关的一些指针（其实是index）定义和用途如下：

```python
# send
self.sdata = [None] * 256   # send data buffer
self.spos = 0               # send position (last available sdata + 1)
self.sbase = 0              # send base
self.snext = 0              # next seq to be sent

# receive
self.rdata = [None] * 256   # receive data buffer
self.rbase = 0              # receive base (not return to app yet)
self.rexpect = 0            # expected next seq
```

这些数据在计算时全都模256进行，所以有些运算会很烦，这是我在实现协议时遇到的主要困难之一。

在发送包时，由于是GBN协议，因此seqNum和ackNum两个字段分别用于表示“本条消息对应的序列号”以及“我希望收到的下一个包的序列号”。这里ackNum是一种累计确认，表示自己之前的所有数据包已经接收完毕。

### 1.3 雏形

最重要的函数显然是send和recv。
我将send、recv、以及一个辅助函数_wait的职能总结如下：

- send：将新的数据安排到 `self.sdata` 数组中（更新 `self.spos`），并在循环中根据窗口大小，发送之前没有发送过的新包（拓展 `self.snext`）。通过调用 `self.wait` 来更新 `self.sbase` ，直到所有将要发送的数据都发送完毕（`self.sbase == self.spos`）。
- recv：`self.rbase` 表示当前没有被返回至上层的最后一个包，`self.rexpect` 表示当前已经可以返回的最后一个包。如果它俩相等，说明现在没有可以返回的包，那么recv会调用 `self.wait` 来更新 `self.rexpect`；否则recv会返回一个包的数据。
- wait：核心函数（不属于API的一部分），负责处理收到的所有包、根据其类型来进行各种操作如发送ACK、存储数据等。其本质是更新 `self.sbase` 和 `self.rexpect`。它有recv模式，在该模式下一次超时就会返回调用者（用于recv）；除此以外，它会在结束或遇到错误（如超时次数过多）时返回false，在 `self.sbase == self.snext` 时（即所有包都确认完毕）返回true。

由于是Go-Back-N协议，因此在wait中，如果发生超时，那么从 `self.sbase` 到 `self.snext` 的所有包都会被重传。

注意：wait是客户端和服务器端都会使用的函数，因此实现了全双工的统一性。

### 1.4 连接

为了标识通信开始、标识通信结束、维护随机化的sbase和rbase，需要实现连接状态。
为了实现连接状态，需要设计连接的开始机制和结束机制。

#### 建立连接

在建立连接时，由客户端向进入listen阶段的服务器端口发送 `flag |= SYN` 的请求建立连接的报文。同时，客户端将会随机化其 `sbase`（初始序列号），并把 `sbase-1` 发送给服务器来让服务器的 `rbase` 与其同步。

```python
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
```

服务器端socket首先需要调用bind来绑定某一端口监听，然后调用listen进入服务器状态。服务器状态下才可以调用 `accept`。（这个设计比较愚蠢，就是为了给listen一个用途而已）

服务器在 `accpet` 中接收到SYN报文后，将会将其 `self.address` 更新为客户端地址，其 `rbase` 更新为 `seqNum + 1`，随机化它自己的 `sbase`，然后向客户端发送 `SYN | ACK` 报文来确认连接。

```python
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

        synack_pack = make_pkt(self.sbase, self.rexpect, b"", start=True, ack=True)
        self.udp_send(synack_pack)
    else:
        print("[error] not SYN")
        return
```

当然，这两条特殊的报文同样要考虑丢包的问题。

在客户端的 `connect` 函数中，如果收不到SYN ACK，就会一直重传SYN包，直到收到 SYN ACK，如下所示：

```python
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
```

而在服务端的 `accpet` 函数中，我没有设置重传，而是将其放在 `wait` 函数中。假设SYN ACK包丢包了，客户端会继续向其发送SYN包，而服务器此时会进入 `wait` 函数进行处理。所以在 `wait` 中，如果收到了SYN包，那么它会重新发送SYN ACK包，在这里实现重传。

#### 断开连接

我设计了两种正常断开连接的方法——主动断开和被动断开。不论是服务器还是客户端，都可以主动断开或被动断开。

主动断开即在连接中调用 `close` 函数。`close` 会向对方发送一个FIN包（通过设置flag中的FIN bit），然后等待对方发来的FIN ACK。

```python
def close(self):
    if (not self.connected):
        print("[info] FIN...")
        return

    # send FIN
    fin_pack = make_pkt(self.snext, self.rexpect, b"", stop=True)
    self.udp_send(fin_pack)

    # wait for FIN ACK
    ...
```

在另一方处理接收到的包的 `wait` 函数中，如果收到了FIN包，那么它会立即进入断开状态，并向其发送一个FIN ACK包。

```python
# handle FIN
elif (flag & FIN):
    ack_pkt = make_pkt((self.snext-1)%256, self.rexpect, b"", ack=True, stop=True)
    self.udp_send(ack_pkt)
    self.udp_socket.settimeout(None)
    self.connected = False
    return False
```

当然，上面两种情景也需要考虑丢包问题。
如果主动发送的FIN包发生丢包，也就是收不到FIN ACK，那么它就会一直重传FIN包。
在我的实现中，FIN ACK包只会发送一次，如果它丢包了就说明主动断开的那一方永远收不到FIN ACK了。因此，我在 `close` 函数中加入了如果超时次数超过 `MAX_TIMEOUT`，就假装自己收到了FIN ACK。从而也断开连接。

```python
# wait for FIN ACK (close函数，接上文)
self.udp_socket.settimeout(self.timeout)
timeout_count = 0
while True:
    if timeout_count >= MAX_TIMEOUT:
        print("[info] FIN...")
        break
    try:
        rcvpkt = self.udp_socket.recv(HEADER_SIZE+BUFFER_SIZE)
        seqNum, ackNum, flag, checksum, data = analyse_pkt(rcvpkt)
        if flag & FIN and flag & ACK and ackNum == self.snext:
            self.connected = False
            print("[info] FIN...")
            break

    except socket.timeout:
        timeout_count += 1
        print("[timeout] FIN ACK")
        self.udp_send(fin_pack)
```

## 2 SR

在SR中，不再使用GBN的累积确认机制，接收方会分别确认每一个收到的包，即使包提前到了也会保存并发送其ACK。此外，对于每一个已发送未确认的包，发送方都会分别维护一个时钟，当某个包的时钟超时了，发送方会单独发送那一个包（所以叫选择重传）。

因此，一个重点是实现（至少逻辑上）分离的时钟，另一个重点就是区分已收到和未收到的包。

### 2.1 时钟

为了实现时钟的逻辑分离，我采用了尽量模拟的方法。我将超时间隔减小，作为类似“普朗克时间”或原子时间的概念。每次超时时，检测每个还在计时的时钟，如果他们超时了就进行重传，然后更新时钟。

我为我的socket添加了一个列表域 `self.sclkq`，全称为send clock queue。它将作为一个队列来使用，其每个元素都是一个 seq：timestamp 的元组。

当一个包（对应一个序列号）在send中被第一次发送时，它的序列号与这时的时间戳组成的元组将会被加入 `sclkq` 的队尾。如下所示：

```python
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
```

当在wait函数中发生了基础超时，程序将会重复检查 `sclkq` 的队首，若当前时间戳与其记录的时间戳差值（也就是距离上次发送过去的时间）超过了设置的超时时间，那么程序将会重传这个序列号的包，并把该元组出列，将其序列号与当前的新时间戳构成的元组重新加入队尾。如下代码所示：

```python
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
        else:
            break
```

这样一来，就实现了发送方对每个包的单独时钟的选择重传。

### 2.2 确认

在SR协议中，ACK表示收到了该序列号的包，而不是累积确认，因此接收方可以提前保存并确认包。如下所示：

```python
# save data
if getChecksum(data) == checksum:
    if self.rdata[seqNum] is None:
        self.rdata[seqNum] = data

    # send ACK
    ack_pkt = make_pkt((self.snext-1)%256, seqNum, b"", ack=True)
    self.udp_send(ack_pkt)

    # update rexpect
    i = self.rexpect
    while not self.rdata[i] is None:
        self.rexpect = (self.rexpect + 1) % 256
        i = self.rexpect
```

注意上段代码中，更新rexpect的方式并不再是简单地加一，而是一直推进到没有收到的地方。区间 $[rbase, rexpect]$ 表示**连续的**可以返回给上层的数据，而rexpect之后可能存在离散的收到的数据，这些数据还不能返回给上层（否则就是乱序了）。

而对于发送方，当接收到ACK时，采用删除其在 `sclkq` 中的元组的方式，来取消其发送。在遍历 `sclkq` 时，同时记录最早的仍在队列中的包 `crt_min_unacked`。如果 `crt_min_unacked` 和 `sbase` 不相等，则说明 `sbase` 可以更新，于是会更新后返回。代码如下：

```python
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
        self.sbase = crt_min_unacked
        self.udp_socket.settimeout(None)
        return True
    else:
        continue
```

### 2.3 拥塞控制

至此，SR协议已经完成了。不过我再加入了一些最基础的拥塞控制机制，也就是AIMD。

我通过修改 `self.window_size` 来完成拥塞控制，`send` 会根据这个变量来决定发不发送新的包。具体的修改位于 `wait` 函数中，Additive Increase位于收到ACK且更新 `sbase` 时，确认数量达到当前的 `self.window_size` 时就会将其加一，代码如下：

```python
# update window size (congestion control)
self.ackcount += (crt_min_unacked - self.sbase) % 256
if self.ackcount >= self.window_size:
    print('[CNG_CTRL] add window size from', self.window_size, 'to', self.window_size+1)
    self.window_size += 1
    self.ackcount = 0
```

而Multiplicative Decrease位于处理一个包超时时，每有一个包超时就会触发这个机制，代码如下：

```python
# update window size (congestion control)
new_window_size = max(2, self.window_size // 2)
print('[CNG_CTRL] reduce window size from', self.window_size, 'to', new_window_size)
self.window_size = new_window_size
```

## 3 测试

我编写了测试脚本用于测试客户端和服务端间连接是否可以准确传输整个图片文件，主要逻辑如下：

```sh
for ((i=1; i<=$num_runs; i++)); do
    rm ./server_log
    rm ./client_log
    python ./sr_server.py 1> ./server_log &
    server_pid=$!

    sleep 1

    python ./sr_client.py 1> ./client_log

    wait $server_pid

    cmp -s ./server/recv.jpg ./client/data.jpg
    if [ $? -eq 0 ]; then
        echo "Test $i: Files match"
    else
        echo "Test $i: Files do not match"
        break
    fi

    sleep 4
done
```

不论是sr客户端与服务器，还是gbn客户端与服务器，都使用该脚本，在丢包率非0的条件下（gbn使用20%测试，sr由于赶ddl原因使用5%测试，高丢包率环境下也测试过没问题）跑过了超过200轮的测试连续正确。

## 总结

一开始尝试在助教提供的实例代码上修改来做实验，但越改越复杂。由于sender和receiver是两个不同的类，因此一些函数复用起来非常烦，有的函数必须要写两遍。

因此我全都推倒重来，除了一些基础的函数以及思路的借鉴外，别的东西全都重新写。尤其是wait函数的复用，自认为比较简洁地实现了我的socket的全双工。

写完后，我对于rdt（以及TCP）的理解确实变得更深了，收获不错。虽然期末季很忙，不过还是抽了时间完成了这个PJ，幸苦自己了hhhh。
