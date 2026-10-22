import struct, socket, datetime, collections, json
P='lalu_lintas_jaringan.pcap'
with open(P,'rb') as f: data=f.read()
magic=data[:4]
endian='<' if magic in (b'\xd4\xc3\xb2\xa1',b'\x4d\x3c\xb2\xa1') else '>'
_,vmaj,vmin,thiszone,sigfigs,snap,network=struct.unpack(endian+'IHHiiii',data[:24])
pos=24; packets=[]; target='45.131.214.85'
while pos+16<=len(data):
 ts_sec,ts_usec,inc,orig=struct.unpack(endian+'IIII',data[pos:pos+16]); pos+=16
 b=data[pos:pos+inc]; pos+=inc
 if len(b)<14: continue
 eth=struct.unpack('!H',b[12:14])[0]; off=14
 if eth==0x8100 and len(b)>=18: eth=struct.unpack('!H',b[16:18])[0]; off=18
 if eth!=0x0800 or len(b)<off+20: continue
 ihl=(b[off]&15)*4; proto=b[off+9]; src=socket.inet_ntoa(b[off+12:off+16]); dst=socket.inet_ntoa(b[off+16:off+20])
 if proto!=6 or len(b)<off+ihl+20: continue
 tcp=off+ihl; sport,dport,seq,ack,flags,win,cs,urg=struct.unpack('!HHIIHHHH',b[tcp:tcp+20]); doff=((flags>>12)&15)*4; payload=b[tcp+doff:]
 t=datetime.datetime.fromtimestamp(ts_sec+ts_usec/1e6,datetime.timezone.utc)
 packets.append((t,src,sport,dst,dport,flags,payload,len(b)))
print('pcap',len(data),'packets tcp_ipv4',len(packets),'range',packets[0][0] if packets else None,packets[-1][0] if packets else None)
sel=[x for x in packets if target in (x[1],x[3]) and (x[2]==443 or x[4]==443)]
print('TARGET_MATCHES',len(sel))
for x in sel[:200]:
 t,src,sp,dst,dp,fl,pay,n=x
 print(t.isoformat(),src,sp,'>',dst,dp,'flags=0x%03x'%fl,'len',n,'payload',len(pay),pay[:80].hex())
print('INTERNAL_ENDPOINT_COUNTS')
c=collections.Counter((x[1],x[2]) for x in sel if x[1].startswith('10.2.28.'))
print(c)
print('ALL_INTERNAL_EXTERNAL_443')
c2=collections.Counter((x[1],x[2],x[3],x[4]) for x in packets if x[1].startswith('10.2.28.') and x[4]==443)
for k,v in c2.most_common(): print(v,k)
