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
    if data == b"ENDDDDD":
        break
    print(len(data))
    f.write(data)

f.close()
s.send(b"Thank you for your data!")
s.close()
