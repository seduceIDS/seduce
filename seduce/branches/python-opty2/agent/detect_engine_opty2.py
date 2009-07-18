''' Inline Python Module to detect Opty2 Encoded Shellcodes
    Also uses opty2values.py supplied by metasploit opty2 package
    15-7-2009
'''

import random
from values import *

def opty2Check(data):
    data = data[::-1]  # reverse string to start checking
    length = len(data)
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
        for selectedList in StateTable[prev]:  # for every list in states table
            found = False
            for token in selectedList:
                if (token & mask) != 0:        # Make some important checking
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
                    
                    index = len(data) - length
                    if byte == ord(data[index]):  #locate suspicious byte
                        print "Suspicious Byte %0x Detected At Index %i with LookUpTable = %i !" % (byte, index, prev)
                        foundByte = byte
                        suspiciousCount += 1	# increment count
                        found = True
                        break
            if found == True:
                break
   	    if found == False:
   	        prev = 256          # if byte was not found, restart with next byte
        if found == True:
            prev = foundByte    # if byte was found, continue with the next
            counts[prev] += 1
        slen   += 1
        length -= 1
    
    percentage = float(( 1.0*suspiciousCount / len(data) )) * 100
    #returns result as a percentage of malicious bytes
    return percentage

	    
