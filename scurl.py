#!/usr/bin/env python2.7

import sys, os, urlparse
import socket
from OpenSSL import SSL, crypto

def main(argv):
  versions = {
    '--tlsv1.0': SSL.TLSv1_METHOD,
    '--tlsv1.1': SSL.TLSv1_1_METHOD,
    '--tlsv1.2': SSL.TLSv1_2_METHOD,
    '--sslv3': SSL.SSLv3_METHOD,
    '-3': SSL.SSLv3_METHOD
  }
  method = SSL.TLSv1_2_METHOD
  ciphers = None
  crlfile = None
  cacert = None
  allow_stale_certs_num = None
  pinnedcertificate = None
  raw_url = None
  port = 443

  # parse agrs
  argc = len(argv)
  i = 0
  while i < argc:
    arg = argv[i]
    if i == argc - 1:
      raw_url = arg
    elif arg in versions.keys():
      method = versions[arg]
    elif arg == "--ciphers":
      i += 1
      if i < argc:
        ciphers = argv[i]
    elif arg == "--crlfile":
      i += 1
      if i < argc:
        crlfile = argv[i]
    elif arg == "--cacert":
      i += 1
      if i < argc:
        cacert = argv[i]
    elif arg == "--allow-stale-certs":
      i += 1
      if i < argc:
        allow_stale_certs_num = argv[i]
    elif arg == "--pinnedcertificate":
      i += 1
      if i < argc:
        pinnedcertificate = argv[i]
    # else:
      # warning 
    i += 1

  # check wrong arguments
  if raw_url is None:
    error("ERROR: no URL specified\n")

  if allow_stale_certs_num is not None:
    if (allow_stale_certs_num < 0) or (not allow_stale_certs_num.is_integer()):
      error("ERROR: allow_stale_certs_num should be a non-negative integer\n")

  url = urlparse.urlparse(raw_url)
  if url.scheme != 'https':
    error("ERROR: URL rejected because scheme is not https\n")
  if url.port is not None:
    port = url.port

  # set context
  context = SSL.Context(method)

  # add ciphers
  if ciphers is not None:
    try:
      context.set_cipher_list(ciphers)
    except:
      error("Invalid ciphers.\n")

  # verify cacert
  if cacert is None:
    context.set_default_verify_paths()
  else:
    context.load_verify_locations(cacert)

  context.set_verify(SSL.VERIFY_PEER, verify_cb)
  
  # SNI features
  sock = SSL.Connection(context, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
  try:
    sock.connect((url.hostname, port))
  except socket.error:
    error("Error when socket connecting.\n")
  sock.set_connect_state()
  sock.set_tlsext_host_name(url.hostname)
  try:
    sock.do_handshake()
  except SSL.Error:
    error("Error in handshake.\n")

  # TODO: check domain matches wildcard/alt names
  # print "2**\n", sock.get_peer_certificate().get_subject().commonName.decode()

  # send and receiver messages
  sock.sendall('GET ' + url.path + ' HTTP/1.0\r\nHost: ' + url.hostname + '\r\nUser-Agent: scurl/yixin\r\nConnection: close\r\n\r\n')
  header = True
  msgs = []
  while 1:
    try:
      msg = sock.recv(1024).decode('utf-8')
      if not header:
        msgs.append(msg)
      elif '\r\n\r\n' in msg:
        header = False
        msgs.append(msg.split('\r\n\r\n', 1)[1])
    except SSL.ZeroReturnError:
      printHTML(msgs)
      break
    except SSL.SysCallError:
      if ''.join(msgs).endswith('</html>'):
        printHTML(msgs)
      else:
        # printHTML(msgs)
        error('Unexpected EOF\n')

  # cleanup
  sock.shutdown()
  sock.close()

def verify_cb(conn, cert, errnum, depth, ok):
  certsubject = crypto.X509Name(cert.get_subject())
  commonname = certsubject.commonName
  # print "1**\n", commonname
  
  # TODO pinnedcertificate
  # TODO check crlfile
  # TODO check expired date
  return ok

def error(msg):
  sys.stderr.write(msg)
  sys.exit(-1)

def printHTML(msgs):
  for msg in msgs:
    sys.stdout.write(msg)
    sys.stdout.flush()

if __name__ == "__main__":
  main(sys.argv[1:])
  exit(0)

