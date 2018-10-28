import socket 
import sys

# Sample BoF tester!
# Milad Fadavvi

usage = "buffer-test.py [IP] [Port]"
buffer = 'A'*10000

if (len(sys.argv) < 3):
    print '\n' + usage + '\n'
    exit(0)
else:  
    Socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        Connection = Socket.connect((sys.argv[1],int(sys.argv[2])))
        Socket.recv(1024)
        Socket.send(buffer + '\r\n')
        print '\n' + "String sent!" + '\n'
        Socket.recv(1024)
        Socket.close()
        exit(1)
    except socket.error as error:
        print '\n' + "Error Detected :" + '\n'
        print error 
        exit(0)

