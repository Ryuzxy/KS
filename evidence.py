import struct,socket,datetime,collections
D=open('lalu_lintas_jaringan.pcap','rb').read(); e='<' if D[:4] in (b'\xd4\xc3\xb2\xa1',b'M<\xb2\xa1') else '>'; p=24; rows=[]; macs=collections.defaultdict(set)
while p+16<=len(D):
 ts,us,inc,orig=struct.unpack(e+'IIII',D[p:p+16]); p+=16; b=D[p:p+inc]; p+=inc
 if len(b)<14: continue
 sm=':'.join(f'{x:02x}' for x in b[6:12]); dm=':'.join(f'{x:02x}' for x in b[:6]); typ=struct.unpack('!H',b[12:14])[0]; o=14
 if typ==0x0806 and len(b)>=42:
  sip=socket.inet_ntoa(b[28:32]); tip=socket.inet_ntoa(b[38:42]); macs[sip].add(sm); macs[tip].add(':'.join(f'{x:02x}' for x in b[32:38])); continue
 if typ!=0x0800 or len(b)<34: continue
 ihl=(b[o]&15)*4; src=socket.inet_ntoa(b[o+12:o+16]); dst=socket.inet_ntoa(b[o+16:o+20]); proto=b[o+9]
 if proto!=6: continue
 t=o+ihl; sp,dp=struct.unpack('!HH',b[t:t+4]); doff=((b[t+12]>>4)&15)*4; pay=b[t+doff:]
 if (src,dst,sp,dp)==('10.2.28.88','45.131.214.85',51912,443) and pay:
  rows.append((datetime.datetime.fromtimestamp(ts+us/1e6,datetime.timezone.utc),pay.decode('latin1'))); macs[src].add(sm)
print('matches',len(rows),'first',rows[0][0],'last',rows[-1][0]); print('macs',dict(macs))
print('FIRST_PAYLOAD\n'+rows[0][1]); print('UNIQUE_PAYLOADS')
for x in sorted(set(v for _,v in rows)): print('---\n'+x)
