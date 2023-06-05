from sr import SRSocket

HOST = 'localhost'
PORT = 8000

s = SRSocket()
s.connect((HOST, PORT))
print('Connect to', s.address)

f = open('client/data.jpg', 'rb')
data = f.read()
f.close()

s.send(data)
s.send(b"ENDDDDD")
print(s.recv().decode())
s.close()
