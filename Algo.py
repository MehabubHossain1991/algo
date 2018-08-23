#Packet sniffer in python for Linux
#Sniffs only incoming TCP packet
import MySQLdb
import socket, sys
from struct import *
from datetime import datetime 
import commands

#Open database connection
db = MySQLdb.connect("localhost","root","mehabub","FIREWALL")
cursor = db.cursor() 

#create an INET, STREAMing socket
#serversocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1) 
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
except socket.error , msg:
    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()

#SHOW CURRENT TIME

now = datetime.now()

#new=datetime.now()

print "Now: Date and TIME", now

# receive a packet

while True:
    packet = s.recvfrom(65565)
     
    #packet string from tuple
    packet = packet[0]
     
    #take first 20 characters for the ip header
    ip_header = packet[0:20]
     
    #now unpack them :)
    iph = unpack('!BBHHHBBH4s4s' , ip_header)
     
    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
     
    iph_length = ihl * 4
     
    ttl = iph[5]
    protocol = iph[6]
    s_addr = socket.inet_ntoa(iph[8]);
    d_addr = socket.inet_ntoa(iph[9]);
     
    #print s_addr
    sip=str(s_addr)
    print sip
    try:

        #FETCHING DUPLICATE IP, IF EXIEST IP
    	sql1="select * from PACKET where IP='"+sip+"'"
    	cursor.execute(sql1)
    	results = cursor.fetchone()
    	if results==None:
         #IF DUPLICATE IP NOT FOUND INSERT THE NEW IP WITH FREQUENCY 1:    
    		sql = "INSERT INTO PACKET VALUES ('"+sip+"','1')"
    		cursor.execute(sql)
    		print "RECORD Inserted Successfully"
    		db.commit()
    	else:
            #IF DUPLICATE IP FOUND THE INCREASE THE FREQUNCCY BY 1
     		tempcount=int(results[1])+1
    		try:
    			cursor.execute("update PACKET set FREQUENCY='"+str(tempcount)+"' where ip='"+sip+"'")
    			print "update  Successfully"
#show start time
    			db.commit()
    		except:
    			print "unable to  update"
    except:
    	print "some error  occured"     
    tcp_header = packet[iph_length:iph_length+20]
     
    #now unpack them :)
    tcph = unpack('!HHLLBBHHH' , tcp_header)
     
    source_port = tcph[0]
    dest_port = tcph[1]
    sequence = tcph[2]
    acknowledgement = tcph[3]
    doff_reserved = tcph[4]
    tcph_length = doff_reserved >> 4
         
#print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length)
     
    h_size = iph_length + tcph_length * 4
    data_size = len(packet) - h_size
     
    #get data from the packet
    data = packet[h_size:]
     
    #print 'Data : ' + data
 
    #appending mode
    f = open("ip.txt", "a")
    f.write(sip + '\n')
    

    new = datetime.now()
  
    h=new.hour-now.hour
    m=new.minute-now.minute
    sec=new.second-now.second

    #print "******************TIME****************",h,m,sec

    if sec<0:
	t=(60-now.second)+new.second
    else:
	t=new.second-now.second

    print "****************TIME*****************",t

    if t>5:
	now=datetime.now()

    	try:
		cursor.execute("select IP from PACKET where frequency>600")
		results = cursor.fetchall()
		print results
		#l1=len(results[0])
		l2=len(results)
 		#print "***Length***",l1 
		print "***Length***",l2
		
		print "Find Successfully"
		for i in range(0,l2):
			#output = commands.getoutput('iptables -A INPUT -s %s -j DROP' %results[0][i])
			print "*****************************************"			
			print i			
			print results[0][i]
		#print results[0][0]

    	except :
		print "Error"
