"""

Course: CSCI-651 : Foundation of Computer Networks
Author: Vinay Jain (vj9898)

Project 2: Write a Ping program from scratch.

NOTE: The assignment's pdf doesn't specify whether we have to build a
program that is capable of handling multiple command line arguments or not.

THEREFORE, I HAVE MADE MY PROGRAM BASED ON HANDLING ONE COMMAND LINE
ARGUMENT AT A TIME.

"""

from _socket import *
from scapy.all import *
from scapy.layers.inet import ICMP, IP
import socket
import sys
import time
from datetime import datetime


"""
The function below is responsible to ping "StringDest" which is the destination.
Code involves
1) get host by the string format of the ping destination
2) create ICMP packet using scapy library
3) send the packet
4) receive response
5) display results of the response, if any
"""
def ping(stringDest, bytesString, mySocket):
    destAddr = gethostbyname(stringDest) # get IP of the host

    # create the ICMP packet and convert it into bytes
    packet = ICMP() / bytesString
    packet = bytes(packet)

    startTime = datetime.now() # start time of sending packet

    mySocket.sendto(packet, (destAddr, 1000)) # packet sent to destAddr

    flag = 0 # flag to know if there was a timeout or not

    try:
        received, recvAddr = mySocket.recvfrom(2048) # response received
    except:
        print("Request Time Out") # time out
        flag = 1 # and hence no response

    if flag == 0: # if valid response was received, display the results
        endTime = datetime.now()

        ttl = list(received)[8]

        diff = endTime - startTime

        print("Ping to " + stringDest + " with IP " + str(destAddr))
        print("Reply from " + str(recvAddr[0]) + ", TTL = " + str(ttl) + ", time: " + str(
            diff.microseconds * 1000) + " ms")


    print()
    print("-----------------") # End of ping
    print()


"""
This function is responsible to change the size of the data that is to be 
sent via the socket to the destination address when pinging. The data would be
resized, in bytes, as given in the command line argument parameters by the user.
If not given, then default length in bytes ios 56 bytes.
"""
def resizePacketData(string, byteLength):
    finalString = "" # string iwth our final result
    currentLength = len(string) # current length of data
    less = 0
    greater = 0

    if byteLength < currentLength: # if the input byte length < current length of data
        less = byteLength
        greater = currentLength

        remainder = int(greater % less)

        for i in range(remainder):
            finalString += string[i % currentLength]

        return bytes(finalString, 'utf-8')
        # return finalString
    elif byteLength > currentLength:  # if the input byte length > current length of data
        less = currentLength
        greater = byteLength

        quotient = int(math.floor(greater / less))
        remainder = int(greater % less)

        finalString = string*quotient

        for i in range(remainder):
            finalString += string[i % currentLength]

        return bytes(finalString, 'utf-8')
        # return finalString
    else:
        return bytes(string, 'utf-8')  # if the input byte length == current length of data
        # return string

"""
This is the main function to call necessary functionalities to 
execute the ping operation.
"""
def main():
    whoToPing = "google.com" # where you want to ping

    # create a socket for ICMP data apacket
    mySocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, getprotobyname("icmp"))

    print("The Ping Program Begins........")
    print()

    # total command line arguments
    n = len(sys.argv)

    # THe data that is to be sen with the ICMP packet
    # By default, this input's length is 56 bytes.
    string = "Hi, I am Vinay Jain and this is a test for ping program."

    # function to resize the data to be sent in the packet
    bytesString = resizePacketData(string, 56) # default = 56 bytes
    if n < 2: # no parameters
        while True: # run ping after every second until interrupted
            ping(whoToPing, bytesString, mySocket)
            time.sleep(1)
    elif sys.argv[1] == "-c": # '-c count' as parameter
        if n == 3:
            count = 0
            var = int(sys.argv[2])
            while count < var: # run ping until count packets pinged
                ping(whoToPing, bytesString, mySocket)
                count += 1
    elif sys.argv[1] == "-i": # '-i seconds' as parameter
        if n == 3:
            var = int(sys.argv[2])
            while True: # run ping after i seconds until interrupted
                ping(whoToPing, bytesString, mySocket)
                time.sleep(var)
    elif sys.argv[1] == "-t": # '-t timeout' as parameter
        # print("arg t")
        if n == 3:
            var = int(sys.argv[2])
            startTime = datetime.now()
            endTime = datetime.now()

            # run ping until timeout
            while int((endTime - startTime).total_seconds()) < var:
                ping(whoToPing, bytesString, mySocket)
                endTime = datetime.now()
    elif sys.argv[1] == "-s": # set the packet's data size
        newSize = int(sys.argv[2])
        bytesString = resizePacketData(string, newSize)

        # run ping with the modified data size until interrupted
        while True:
            ping(whoToPing, bytesString, mySocket)

    mySocket.close() # close the socket


main() # initiate the program for PING execution