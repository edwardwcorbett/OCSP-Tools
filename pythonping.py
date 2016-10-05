import os
import sys
import time
import array
import socket
import struct
import select
import signal
try:
    from _thread import get_ident
except ImportError:
    def get_ident(): return 0

if sys.platform == "win32":
    # On Windows, the best timer is time.clock()
    default_timer = time.clock
else:
    # On most other platforms the best timer is time.time()
    default_timer = time.time

#=============================================================================#
# ICMP parameters

ICMP_ECHOREPLY = 0		# Echo reply (per RFC792)
ICMP_ECHO = 8			# Echo request (per RFC792)
ICMP_ECHO_IPV6 = 128		# Echo request (per RFC4443)
ICMP_ECHO_IPV6_REPLY = 129	# Echo request (per RFC4443)
ICMP_MAX_RECV = 2048		# Max size of incoming buffer

MAX_SLEEP = 1000

class MyStats:
    thisIP = "0.0.0.0"
    pktsSent = 0
    pktsRcvd = 0
    minTime = 999999999
    maxTime = 0
    totTime = 0
    avrgTime = 0
    fracLoss = 1.0

myStats = MyStats # NOT Used globally anymore.

#=============================================================================#
def checksum(source_string):
    """
    A port of the functionality of in_cksum() from ping.c
    Ideally this would act on the string as a series of 16-bit ints (host
    packed), but this works.
    Network data is big-endian, hosts are typically little-endian
    """
    if (len(source_string) % 2):
        source_string += "\x00"
    converted = array.array("H", source_string)
    if sys.byteorder == "big":
        converted.bytewap()
    val = sum(converted)

    val &= 0xffffffff # Truncate val to 32 bits (a variance from ping.c, which
                      # uses signed ints, but overflow is unlikely in ping)

    val = (val >> 16) + (val & 0xffff)    # Add high 16 bits to low 16 bits
    val += (val >> 16)                    # Add carry from above (if any)
    answer = ~val & 0xffff                # Invert and truncate to 16 bits
    answer = socket.htons(answer)

    return answer

#=============================================================================#
def do_one(myStats, destIP, hostname, timeout, mySeqNumber, numDataBytes, quiet = False, ipv6=False):
    """
    Returns either the delay (in ms) or None on timeout.
    """
    delay = None

    if ipv6:
        try: # One could use UDP here, but it's obscure
            mySocket = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.getprotobyname("ipv6-icmp"))
            mySocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        #except socket.error
        except OSError as e:
            #etype, evalue, etb = sys.exc_info()
            print("failed. (socket error: '%s')" % str(e))#evalue.args[1])
            print('Note that python-ping uses RAW sockets'
                    'and requiers root rights.')
            raise # raise the original error
    else:

        try: # One could use UDP here, but it's obscure
            mySocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
            mySocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        #except socket.error:
        except OSError as e:
            #etype, evalue, etb = sys.exc_info()
            print("failed. (socket error: '%s')" % str(e))#evalue.args[1])
            print('Note that python-ping uses RAW sockets'
                    'and requires root rights.')
            raise # raise the original error

    #my_ID = os.getpid() & 0xFFFF
    my_ID = (os.getpid() ^ get_ident()) & 0xFFFF

    sentTime = send_one_ping(mySocket, destIP, my_ID, mySeqNumber, numDataBytes, ipv6)
    if sentTime == None:
        mySocket.close()
        return delay

    myStats.pktsSent += 1

    recvTime, dataSize, iphSrcIP, icmpSeqNumber, iphTTL = receive_one_ping(mySocket, my_ID, timeout, ipv6)

    mySocket.close()

    if recvTime:
        delay = (recvTime-sentTime)*1000
        if not quiet:
            if ipv6:
                host_addr = hostname
            else:
                try:
                    host_addr = socket.inet_ntop(socket.AF_INET, struct.pack("!I", iphSrcIP))
                except AttributeError:
                    # Python on windows dosn't have inet_ntop.
                    host_addr = hostname

            print("%s " % (host_addr))
            f1.write(host_addr + "\n")

        myStats.pktsRcvd += 1
        myStats.totTime += delay
        if myStats.minTime > delay:
            myStats.minTime = delay
        if myStats.maxTime < delay:
            myStats.maxTime = delay
    #else:
     #   delay = None
      #  if not quiet:
       #     print("Request timed out.")

    return delay

#=============================================================================#
def send_one_ping(mySocket, destIP, myID, mySeqNumber, numDataBytes, ipv6=False):
    """
    Send one ping to the given >destIP<.
    """
    #destIP  =  socket.gethostbyname(destIP)

    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    # (numDataBytes - 8) - Remove header size from packet size
    myChecksum = 0

    # Make a dummy heder with a 0 checksum.
    if ipv6:
        header = struct.pack(
            "!BbHHh", ICMP_ECHO_IPV6, 0, myChecksum, myID, mySeqNumber
        )
    else:
        header = struct.pack(
            "!BBHHH", ICMP_ECHO, 0, myChecksum, myID, mySeqNumber
        )

    padBytes = []
    startVal = 0x42
    # 'cose of the string/byte changes in python 2/3 we have
    # to build the data differnely for different version
    # or it will make packets with unexpected size.
    if sys.version[:1] == '2':
        bytes = struct.calcsize("d")
        data = ((numDataBytes - 8) - bytes) * "Q"
        data = struct.pack("d", default_timer()) + data
    else:
        for i in range(startVal, startVal + (numDataBytes - 8)):
            padBytes += [(i & 0xff)]  # Keep chars in the 0-255 range
        #data = bytes(padBytes)
        data = bytearray(padBytes)


    # Calculate the checksum on the data and the dummy header.
    myChecksum = checksum(header + data) # Checksum is in network order

    # Now that we have the right checksum, we put that in. It's just easier
    # to make up a new header than to stuff it into the dummy.
    if ipv6:
        header = struct.pack(
            "!BbHHh", ICMP_ECHO_IPV6, 0, myChecksum, myID, mySeqNumber
        )
    else:
        header = struct.pack(
            "!BBHHH", ICMP_ECHO, 0, myChecksum, myID, mySeqNumber
        )

    packet = header + data

    sendTime = default_timer()

    try:
        mySocket.sendto(packet, (destIP, 1)) # Port number is irrelevant for ICMP
    #except socket.error:
    except OSError as e:
        #etype, evalue, etb = sys.exc_info()
        print("General failure (%s)" % str(e))#(evalue.args[1]))
        return

    return sendTime

#=============================================================================#
def receive_one_ping(mySocket, myID, timeout, ipv6 = False):
    """
    Receive the ping from the socket. Timeout = in ms
    """
    timeLeft = timeout/1000

    while True: # Loop while waiting for packet or timeout
        startedSelect = default_timer()
        whatReady = select.select([mySocket], [], [], timeLeft)
        howLongInSelect = (default_timer() - startedSelect)
        if whatReady[0] == []: # Timeout
            return None, 0, 0, 0, 0

        timeReceived = default_timer()

        recPacket, addr = mySocket.recvfrom(ICMP_MAX_RECV)

        ipHeader = recPacket[:20]
        iphVersion, iphTypeOfSvc, iphLength, \
        iphID, iphFlags, iphTTL, iphProtocol, \
        iphChecksum, iphSrcIP, iphDestIP = struct.unpack(
            "!BBHHHBBHII", ipHeader
        )

        if ipv6:
            icmpHeader = recPacket[0:8]
        else:
            icmpHeader = recPacket[20:28]

        icmpType, icmpCode, icmpChecksum, \
        icmpPacketID, icmpSeqNumber = struct.unpack(
            "!BBHHH", icmpHeader
        )

        # Match only the packets we care about
        if (icmpType != 8) and (icmpPacketID == myID):
        #if icmpPacketID == myID: # Our packet
            dataSize = len(recPacket) - 28
            #print (len(recPacket.encode()))
            return timeReceived, (dataSize + 8), iphSrcIP, icmpSeqNumber, iphTTL

        timeLeft = timeLeft - howLongInSelect
        if timeLeft <= 0:
            return None, 0, 0, 0, 0

#=============================================================================#
def dump_stats(myStats):
    """
    Show stats when pings are done
    """
    #print("\n----%s PYTHON PING Statistics----" % (myStats.thisIP))

    #if myStats.pktsSent > 0:
    #    myStats.fracLoss = (myStats.pktsSent - myStats.pktsRcvd)/myStats.pktsSent

    #print("%d packets transmitted, %d packets received, %0.1f%% packet loss" % (
    #    myStats.pktsSent, myStats.pktsRcvd, 100.0 * myStats.fracLoss
    #))

    #if myStats.pktsRcvd > 0:
     #   print("round-trip (ms)  min/avg/max = %d/%0.1f/%d" % (
     #       myStats.minTime, myStats.totTime/myStats.pktsRcvd, myStats.maxTime
     #   ))

    #print("")
    return

#=============================================================================#
def signal_handler(signum, frame):
    """
    Handle exit via signals
    """
    dump_stats(myStats)
    print("\n(Terminated with signal %d)\n" % (signum))
    sys.exit(0)

#=============================================================================#
def verbose_ping(hostname, timeout = 3000, count = 1,
                     numDataBytes = 64, path_finder = False, ipv6=False):
    """
    Send >count< ping to >destIP< with the given >timeout< and display
    the result.
    """
    signal.signal(signal.SIGINT, signal_handler)   # Handle Ctrl-C
    if hasattr(signal, "SIGBREAK"):
        # Handle Ctrl-Break e.g. under Windows
        signal.signal(signal.SIGBREAK, signal_handler)

    myStats = MyStats() # Reset the stats

    mySeqNumber = 0 # Starting value

    try:
        if ipv6:
            info = socket.getaddrinfo(hostname, None)[0]
            destIP = info[4][0]
        else:
            destIP = socket.gethostbyname(hostname)
        #print("\nPYTHON PING %s (%s): %d data bytes" % (hostname, destIP, numDataBytes))
    except socket.gaierror as e:
        #etype, evalue, etb = sys.exc_info()
        #print("\nPYTHON PING: Unknown host: %s (%s)" % (hostname, str(e))) #(hostname, evalue.args[1]))
        print()
        return

    myStats.thisIP = destIP

    for i in range(count):
        delay = do_one(myStats, destIP, hostname, timeout,
                         mySeqNumber, numDataBytes, ipv6=ipv6)
        if delay is None:
            delay = 0

        mySeqNumber += 1

        # Pause for the remainder of the MAX_SLEEP period (if applicable)
        if (MAX_SLEEP > delay):
            time.sleep((MAX_SLEEP - delay)/1000)

    dump_stats(myStats)
    # 0 if we receive at least one packet
    # 1 if we don't receive any packets
    return not myStats.pktsRcvd

#=============================================================================#
def quiet_ping(hostname, timeout = 3000, count = 1,
                     numDataBytes = 64, path_finder = False, ipv6 = False):
    """
    Same as verbose_ping, but the results are returned as tuple
    """
    myStats = MyStats() # Reset the stats
    mySeqNumber = 0 # Starting value

    try:
        if ipv6:
            info = socket.getaddrinfo(hostname, None)[0]
            destIP = info[4][0]
        else:
            destIP = socket.gethostbyname(hostname)
    except socket.gaierror:
        return False

    myStats.thisIP = destIP

    # This will send packet that we dont care about 0.5 seconds before it starts
    # acrutally pinging. This is needed in big MAN/LAN networks where you sometimes
    # loose the first packet. (while the switches find the way... :/ )
    if path_finder:
        fakeStats = MyStats()
        do_one(fakeStats, destIP, hostname, timeout,
                        mySeqNumber, numDataBytes, quiet=True, ipv6=ipv6)
        time.sleep(0.5)

    for i in range(count):
        delay = do_one(myStats, destIP, hostname, timeout,
                        mySeqNumber, numDataBytes, quiet=True, ipv6=ipv6)

        if delay is None:
            delay = 0

        mySeqNumber += 1

        # Pause for the remainder of the MAX_SLEEP period (if applicable)
        if (MAX_SLEEP > delay):
            time.sleep((MAX_SLEEP - delay) / 1000)

    if myStats.pktsSent > 0:
        myStats.fracLoss = (myStats.pktsSent - myStats.pktsRcvd) / myStats.pktsSent
    if myStats.pktsRcvd > 0:
        myStats.avrgTime = myStats.totTime / myStats.pktsRcvd

    # return tuple(max_rtt, min_rtt, avrg_rtt, percent_lost)
    return myStats.maxTime, myStats.minTime, myStats.avrgTime, myStats.fracLoss

#=============================================================================#
if __name__ == '__main__':
    net = str(raw_input("Input ip network : "))
    if len(sys.argv) == 1:
	f1=open('./iplist.txt', 'w+')
	for ip in range(1,255):
        # These should work:
		current= net + str(ip)
        	verbose_ping(current)

	f1.close()
        #verbose_ping("heise.de")
        #verbose_ping("google.com")

        # Inconsistent on Windows w/ ActivePython (Python 3.2 resolves correctly
        # to the local host, but 2.7 tries to resolve to the local *gateway*)
        #verbose_ping("localhost")

        # Should fail with 'getaddrinfo failed':
        #verbose_ping("foobar_url.foobar")

        # Should fail (timeout), but it depends on the local network:
        #verbose_ping("192.168.255.254")

        # Should fails with 'The requested address is not valid in its context':
        #verbose_ping("0.0.0.0")
    #elif len(sys.argv) == 2:
        #retval = verbose_ping(sys.argv[1])
        #sys.exit(retval)
    #else:
        #print("Error: call ./ping.py hostname")
