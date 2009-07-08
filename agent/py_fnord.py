''' Inline Python Module to detect Fnord Encoded Shellcodes
    Based on the original Dragos Ruiu fnord plugin
    Also uses values.py supplied by metasploit opty2 package
'''

import random
from values import *

def fnordCheck(data):
    #for letter in data:
    #    print hex(ord(letter)),
    data = data[::-1]  # reverse string to start checking
    length = len(data)
    #print "Data Packet length is %i" % len(data)
    sled = ''
    prev = 256
    slen = 0
    suspiciousCount = 0
    foundByte = 0

    counts=[]
    for i in range(1,256):
        counts.append(0)

    mask = 3145728
    bad_bytes = []

    while length > 0:
        low  = -1
        lows = []   
        for selectedList in StateTable[prev]:
            found = False
            for token in selectedList:
                if (token & mask) != 0:    
                    continue
                if (((token >> 8) & 0xff) > slen):   
                    continue
                byte = token & 0xff
                if (low == -1) or (low > counts[byte]):
                    low  = counts[byte]
                    lows = [byte]
                elif low == counts[byte]:
                    lows.reverse
                    lows.append(byte)
                    lows.reverse
                    #print lows
                    
                    index = len(data) - length
                    #print index
                    #var = raw_input("proxora.. ")
                    if byte == ord(data[index]):
                        print "Suspicious Byte %0x Detected At Index %i with LookUpTable = %i !" % (byte, index, prev)
                        foundByte = byte
                        suspiciousCount += 1	
                        found = True
                        break
            if found == True:
                break
   	    if found == False:
   	        prev = 256
        if found == True:
            #print "Found Byte is %0x with LookUpTable = %i" % (foundByte,prev)
            prev = foundByte
            #print "New prev is %i" % foundByte
            counts[prev] += 1
        slen   += 1
        length -= 1

    #print "%s out of %s bytes were detected !" % (suspiciousCount, len(data))
    
    percentage = float(( 1.0*suspiciousCount / len(data) )) * 100
    return percentage

	    