from gbn import GBNSocket

HOST = 'localhost'
PORT = 8000

s = GBNSocket()
s.bind((HOST, PORT))

s.listen()
s.accept()
print('Connected by', s.address)

f = open('server/recv.jpg', 'wb')
while True:
    data = s.recv()
    if not data:
        break
    f.write(data)

f.close()
s.close()
