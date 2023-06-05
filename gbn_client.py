from gbn import GBNSocket

HOST = 'localhost'
PORT = 8000

s = GBNSocket()
s.connect((HOST, PORT))
print('Connect to', s.address)

f = open('client/data.jpg', 'rb')
data = f.read()
f.close()

s.send(data)
s.close()
