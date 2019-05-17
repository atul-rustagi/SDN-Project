import socket
import optparse
import time

class DNSQuery:
  def __init__(self, data):
    self.data=data
    self.dominio=''
    self.DnsType=''

    HDNS=data[-4:-2].encode("hex")
    if HDNS == "0001":
      self.DnsType='A'
    elif HDNS == "000f":
      self.DnsType='MX'
    elif HDNS == "0002":
      self.DnsType='NS'
    elif HDNS == "0010":
       self.DnsType="TXT"
    else:
      self.DnsType="Unknown"

    tipo = (ord(data[2]) >> 3) & 15   # Opcode bits
    if tipo == 0:                     # Standard query
      ini=12
      lon=ord(data[ini])
      while lon != 0:
        self.dominio+=data[ini+1:ini+lon+1]+'.'
        ini+=lon+1
        lon=ord(data[ini])

  def respuesta(self, ip):
    packet=''
    if self.dominio:
      packet+=self.data[:2] + "\x81\x80"
      packet+=self.data[4:6] + self.data[4:6] + '\x00\x00\x00\x00'   # Questions and Answers Counts
      packet+=self.data[12:]                                         # Original Domain Name Question
      packet+='\xc0\x0c'                                             # Pointer to domain name
      packet+='\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'             # Response type, ttl and resource data length -> 4 bytes
      packet+=str.join('',map(lambda x: chr(int(x)), ip.split('.'))) # 4bytes of IP
    return packet

if __name__ == '__main__':
  parser = optparse.OptionParser()
  parser.add_option("-f", "--filename", action="store", type="string",dest="SaveFile", help="input a filename to log output too")
  (options, args) = parser.parse_args()
  
  ip='192.168.1.1'
  print('pyminifakeDNS:: dom.query. 60 IN A %s' % ip)
  
  udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  udps.bind(('',53))
  
  try:
    while 1:
      data, addr = udps.recvfrom(1024)
      p=DNSQuery(data)
      udps.sendto(p.respuesta(ip), addr)
      print( 'Respuesta: %s -> %s -> %s -> %s' % (addr[0], p.DnsType, p.dominio, ip))
      if options.SaveFile:
        MyDate=time.strftime('%Y %m %d')
        MyTime=time.strftime('%H:%M:%S')
        logfile = open(options.SaveFile,"a")
        logfile.write('%s,%s,%s,%s,%s,%s\n' % (MyDate,MyTime,addr[0], p.DnsType,p.dominio,ip))
        logfile.close 
  except KeyboardInterrupt:
    print ('Finalizando')
udps.close()
