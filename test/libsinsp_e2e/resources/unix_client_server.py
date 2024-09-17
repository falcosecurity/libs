#!/usr/bin/python3
# coding: utf-8 -*-
import socket
import os, os.path
import sys

PAYLOAD = "0123456789QWERTYUIOPASDFGHJKLZXCVBNM"
NAME = "/tmp/python_unix_sockets_example"
STARTED = "STARTED"

if sys.argv[1] == 'server':
  if os.path.exists(NAME):
    os.remove(NAME)

  server = socket.socket( socket.AF_UNIX, socket.SOCK_STREAM )
  server.bind(NAME)

  print(STARTED)
  server.listen(5)

  connect, address = server.accept()
  resp = connect.recv( 1024 )
  connect.send(resp)
  connect.close()
  server.close()
  os.remove(NAME)

else:
  if os.path.exists(NAME):
    client = socket.socket( socket.AF_UNIX, socket.SOCK_STREAM )
    client.connect(NAME)

    print(STARTED)

    client.send(PAYLOAD.encode())
    resp = client.recv(1024)
    client.close()

  else:
    print("Couldn't Connect!", file=sys.stderr)
