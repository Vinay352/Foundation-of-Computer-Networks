"""

Course: CSCI-651 : Foundation of Computer Networks
Author: Vinay Jain (vj9898)

Project 2: Write a Traceroute program from scratch.

NOTE: The assignment's pdf doesn't specify whether we have to build a
program that is capable of handling multiple command line arguments or not.

THEREFORE, I HAVE MADE MY PROGRAM BASED ON HANDLING ONE COMMAND LINE
ARGUMENT AT A TIME.


ANOTHER NOTE: As per the assignment pdf, I couldn't really comprehend
the proper meaning of using this program with '-n' parameter.
"Print hop addresses numerically rather than symbolically and numerically."

THEREFORE, I JUST EXECUTED THE NORMAL TRACEROUTE PROGRAM WITH 3 REATTEMPTS FOR
EVERY HOP FOR THIS COMMAND LINE ARGUMENT.
"""


from _socket import *
from scapy.all import *
from scapy.layers.inet import ICMP, IP
import socket
import sys
import time
from datetime import datetime


"""
This function is responsible for exeuting the main logic behind traceroute/
1) Create the socket to send ICMP data packets
2) Set the timeout for the socket
3) For every hop, make 'nqueries' attempt to establish a connection
4) send the packet
5) receive the paket, if connection established
6) print results as per the response
"""
def traceroute(destAddr, maxHops = 30, nqueries = 3):
    # Create the socket to send ICMP data packets
    mySocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, getprotobyname("icmp"))
    mySocket.settimeout(5) # Set the timeout for the socket

    destAddr = gethostbyname(destAddr) # get ip of the destination

    notAnsweredProbesList = [] # to measure unanswered connection attempts per hop

    breakFlag = 0

    # For every hop (TTL)
    for ttl in range(1, maxHops + 1):
        notAnsweredProbes = 0 # to measure unanswered connection attempts

        # make 'nqueries' attempt to establish a connection
        for i in range(nqueries):
            flag = 0

            # set the socket's TTL count
            mySocket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

            # create the ICMP packet using scapy
            packet = ICMP() / b"This is a test for tracerouter."

            startTime = datetime.now()

            packet = bytes(packet)

            mySocket.sendto(packet, (destAddr, 1000)) # send the packet

            try:
                received, recvAddr = mySocket.recvfrom(2048) # receive the packet
            except:
                print("" + str(ttl) + " Request Timed Out") # No response within timeout
                notAnsweredProbes += 1 # no reply count increase
                flag = 1
            finally:
                if flag == 0:
                    endTime = datetime.now()

                    diff = endTime - startTime

                    ip = recvAddr[0]

                    print("" + str(ttl) + "ttl, from " + str(ip) + " , in " + str(diff.microseconds * 1000) + " ms")

                    if recvAddr[0] == destAddr: # if reached the destination address
                        breakFlag = 1
                        break
        if breakFlag == 1:
            break

        notAnsweredProbesList.append(notAnsweredProbes)

    mySocket.close()

    return notAnsweredProbesList

"""
This is the main function to call necessary functionalities to 
execute the traceroute operation.
"""
def main():
    whoToTraceroute = "google.com" # where you want to ping

    print("The Traceroute Program Begins........")
    print()

    numberOfHops = 119 # max number of hops for the traceroute program
    numberOfReattempts = 3 # number of reattempts for every hop

    n = len(sys.argv) # total command line arguments

    if n < 2: # no parameters
        traceroute(whoToTraceroute, numberOfHops, numberOfReattempts)
    else:
        if sys.argv[1] == "-q": # specify number of reattempts for every hop in traceroute
            nqueries = int(sys.argv[2])
            traceroute(whoToTraceroute, numberOfHops, nqueries)
        elif sys.argv[1] == "-S": # give summary of non answered attempts for every hop
            notAnsweredProbesList = traceroute(whoToTraceroute, numberOfHops, numberOfReattempts)
            print()
            for i in range(len(notAnsweredProbesList)):
                print("For TTL " + str(i + 1) + ", not answered Probes = " + str(notAnsweredProbesList[i]))
        elif sys.argv[1] == "-n": # refer the "ANOTHER NOTE" at the top
            traceroute(whoToTraceroute, numberOfHops, numberOfReattempts)


main() # initiate the program for TRACEROUTE execution