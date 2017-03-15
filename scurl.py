#!/usr/bin/env python2.7

import sys, os, urlparse
import socket
import re
from OpenSSL import SSL, crypto
import datetime

crlfile = None
crl_list = None
allow_stale_certs_num = None
pinnedcertificate = None
pinned_cert_hash = None
hostname = None

def main(argv):
  versions = {
    '--tlsv1.0': SSL.TLSv1_METHOD,
    '--tlsv1.1': SSL.TLSv1_1_METHOD,
    '--tlsv1.2': SSL.TLSv1_2_METHOD,
    '--sslv3': SSL.SSLv3_METHOD,
    '-3': SSL.SSLv3_METHOD
  }

  global crlfile
  global crl_list
  global allow_stale_certs_num
  global pinnedcertificate
  global pinned_cert_hash
  global hostname
  method = SSL.TLSv1_2_METHOD
  ciphers = None
  cacert = None
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
        allow_stale_certs_num = int(argv[i])
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

  if pinnedcertificate is not None:
    crlfile = None
    allow_stale_certs_num = None
    cacert = None
    try:
      with open(pinnedcertificate) as f:
        buffer = f.read()
      pinned_cert_hash = crypto.load_certificate(crypto.FILETYPE_PEM, buffer).digest("sha256")
      f.close()
    except IOError:
      error("IOError when reading files.\n")

  if allow_stale_certs_num is not None:
    if allow_stale_certs_num < 0:
      error("ERROR: allow_stale_certs_num should be a non-negative integer\n")

  if crlfile is not None:
    try:
      with open(crlfile) as f1:
        buffer1 = f1.read()
      crl_list = crypto.load_crl(crypto.FILETYPE_PEM, buffer1).get_revoked()
      f1.close()
    except IOError:
      error("IOError when reading files.\n")

  url = urlparse.urlparse(raw_url)
  if url.scheme != 'https':
    error("ERROR: URL rejected because scheme is not https\n")
  if url.port is not None:
    port = url.port
  hostname = url.hostname

  # set context
  context = SSL.Context(method)

  # add ciphers
  if ciphers is not None:
    try:
      context.set_cipher_list(ciphers)
    except:
      error("Invalid ciphers.\n")

  # add cacert
  if cacert is None:
    context.set_default_verify_paths()
  else:
    context.load_verify_locations(cacert)

  # verify during handshake
  context.set_verify(SSL.VERIFY_PEER, verify_cb)
  
  # connect with SNI features
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
    error("Error: verification failed or and unexpected error in handshake.\n")
  # except:
    # error("Unexpected errors in handshake.\n")

  if not checkMatch(sock.get_peer_certificate(), url.hostname):
    error("Error in domain matches in certificates.\n")

 # send and receiver messages
  sock.sendall('GET ' + url.path + ' HTTP/1.0\r\nHost: ' + url.hostname + '\r\nUser-Agent: scurl/yixin\r\nAccept: */*\r\nConnection: close\r\n\r\n')
  header = True
  msgs = []
  while 1:
    try:
      msg = sock.recv(1024)
      if not header:
        msgs.append(msg)
      elif '\r\n\r\n' in msg:
        header = False
        msgs.append(msg.split('\r\n\r\n', 1)[1])
    except SSL.ZeroReturnError:
      printHTML(msgs)
      break
    except SSL.SysCallError as e:
      if e[1] == 'Unexpected EOF':
        printHTML(msgs)
        break
      else:
        error('Syscall error, not EOF\n')
    except SSL.Error:
      error('Other unexpected errors when receiving messages.\n')

  # cleanup
  sock.shutdown()
  sock.close()

def checkMatch(cert, hostname):
  # check commonName
  commonName = cert.get_subject().commonName.decode()
  pattern = r'^[^.]*\.?' + commonName.replace('.', '\.')[3:] + '(?:$|\s)'
  match = re.search(pattern, hostname)
  if hostname == commonName or match:
    return True
  length = cert.get_extension_count()
  for i in range(length):
    ext = cert.get_extension(i)
    if ext.get_short_name() == "subjectAltName":
      alt = ext._subjectAltNameString()
      alt_list = alt.split(', ')
      # check match
      for item in alt_list:
        item = item[4:] #remove DNS:
        if hostname in item:
          return True
        pattern = r'^[^.]*\.?' + item.replace('.', '\.')[3:] + '(?:$|\s)'
        match = re.search(pattern, hostname)
        if match:
          return True
      break
  return False

def verify_cb(conn, cert, errnum, depth, ok):
  certsubject = crypto.X509Name(cert.get_subject())
  commonname = certsubject.commonName
  #print "1**\n", commonname
  if pinnedcertificate is not None:
    # check pinned certificate
    if depth == 0:
      # load certificate
      cert_hash = cert.digest("sha256")
      return (pinned_cert_hash == cert_hash)
    else:
      return True
  else:
    # if depth == 0:
      # TODO check name match
      # return ok
    # check crl
    if crlfile is not None:
      serial_number_to_hex_str = str(format(cert.get_serial_number(), 'X'))
      for revoke in crl_list:
        if revoke.get_serial() == serial_number_to_hex_str:
          return False

    # allow expired certificate
    if allow_stale_certs_num is not None and cert.has_expired():
      expired_time = datetime.datetime.strptime(cert.get_notAfter(), "%Y%m%d%H%M%SZ")
      new_time = expired_time + datetime.timedelta(days = allow_stale_certs_num)
      return new_time > datetime.datetime.utcnow()
  
  # Nothing is detected
  return ok

def error(msg):
  sys.stderr.write(msg)
  sys.stdout.flush()
  sys.exit(-1)

def printHTML(msgs):
  for msg in msgs:
    sys.stdout.write(msg)
    sys.stdout.flush()

if __name__ == "__main__":
  main(sys.argv[1:])
  exit(0)

