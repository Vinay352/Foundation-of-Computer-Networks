"""

Course: CSCI-651 : Foundation of Computer Networks
Author: Vinay Jain (vj9898)

Project 1

"""


from scapy.all import rdpcap
from scapy.layers.l2 import Ether
from scapy.utils import hexdump, import_hexcap
import math
import sys


def getPacketSize(tempPacketHexDump):
    splitStringAtLine = tempPacketHexDump.split("\n")
    # print(tempPacketHexDump)
    # print(splitStringAtLine)
    # print(len(splitStringAtLine))
    # print()

    lastLine = splitStringAtLine[-1]
    lastLine = lastLine.split(" ")
    # print(lastLine)
    # print(len(lastLine))

    lineCount = int(lastLine[0][:-1], 16)
    lastLineElementCount = 0
    for i in lastLine[2:]:
        if i != "":
            lastLineElementCount += 1
        else:
            break
    # print(lastLineElementCount)

    packetSize = lastLineElementCount + (lineCount * 16)
    return packetSize, splitStringAtLine


def udpFunction(udpStringTemp, port):
    udpStringTemp = udpStringTemp.split(" ")
    udpString = "UDP: ---- UDP Header ----\nUDP: \n"

    sourcePort_final = ""
    destPort_final = ""
    length_final = ""
    checksum_final = ""

    sourcePortUDP = 0
    destPortUDP = 0
    lengthUDP = 0
    checksumUDP = 0

    sourcePort = ""
    destPort = ""
    length = ""
    checksum = ""

    answer = "False"

    for hexPairCount in range(len(udpStringTemp)):
        hexValue = udpStringTemp[hexPairCount]

        if hexPairCount >= 0 and hexPairCount <= 1:
            sourcePort += hexValue
        if hexPairCount == 1 and sourcePortUDP == 0:
            sourcePort_final = "UDP: Source Port = " + str(int(sourcePort, 16)) + "\n"
            sourcePortUDP = 1

        if hexPairCount >= 2 and hexPairCount <=3:
            destPort += hexValue
        if hexPairCount == 3 and destPortUDP == 0:
            destPort_final = "UDP: Destination Port = " + str(int(destPort, 16)) + "\n"
            destPortUDP = 1

        if hexPairCount >=4 and hexPairCount <=5:
            length += hexValue
        if hexPairCount == 5 and lengthUDP == 0:
            length_final = "UDP: Length = " + str(int(length, 16)) + "\n"
            lengthUDP = 1

        if hexPairCount >= 6 and hexPairCount <= 7:
            checksum += hexValue
        if hexPairCount == 7 and checksumUDP == 0:
            checksum_final = "UDP: Checksum = " + checksum + "\n"
            checksumUDP = 1

        if port in destPort or port in sourcePort:
            answer = "True"

    udpString += sourcePort_final + destPort_final + length_final + checksum_final + "UDP: \n"
    return udpString, answer


def tcpFunction(tcpStringTemp, port):
    tcpStringTemp = tcpStringTemp.split(" ")
    tcpString = "TCP: ---- TCP Header ----\nTCP: \n"

    answer = "False"

    sourcePort_final = ""
    destPort_final = ""
    seqNumber_final = ""
    ackNumber_final = ""
    dataOffset_final = ""
    flags_final = ""
    urgentPointerStatus = ""
    ackStatus = ""
    pushStatus = ""
    resetStatus = ""
    synStatus = ""
    finStatus = ""
    window_final = ""
    checksum_final = ""

    sourcePortTCP = 0
    destPortTCP = 0
    seqNumberTCP = 0
    ackNumberTCP = 0
    windowTCP = 0
    checksumTCP = 0
    urgentPointTCP = 0

    sourcePort = ""
    destPort = ""
    seqNumber = ""
    ackNumber = ""
    dataOffset = ""
    window = ""
    urgentPoint = ""
    checksum = ""
    flags = ""

    for hexPairCount in range(len(tcpStringTemp)):
        hexValue = tcpStringTemp[hexPairCount]

        if hexPairCount >= 0 and hexPairCount <= 1:
            sourcePort += hexValue
        if hexPairCount == 1 and sourcePortTCP == 0:
            sourcePort_final = "TCP: Source Port = " + str(int(sourcePort, 16)) + "\n"
            sourcePortTCP = 1

        if hexPairCount >= 2 and hexPairCount <= 3:
            destPort += hexValue
        if hexPairCount == 3 and destPortTCP == 0:
            destPort_final = "TCP: Destination Port = " + str(int(destPort, 16)) + "\n"
            destPortTCP = 1

        if hexPairCount >= 4 and hexPairCount <= 7:
            seqNumber += hexValue
        if hexPairCount == 7 and seqNumberTCP == 0:
            seqNumber_final = "TCP: Sequence Number = " + str(int(seqNumber, 16)) + "\n"
            seqNumberTCP = 1

        if hexPairCount >= 8 and hexPairCount <= 11:
            ackNumber += hexValue
        if hexPairCount == 11 and ackNumberTCP == 0:
            ackNumber_final = "TCP: Acknowledgement Number = " + str(int(ackNumber, 16)) + "\n"
            ackNumberTCP = 1

        if hexPairCount == 12:
            dataOffset += hexValue
            dataOffset_final = "TCP: Data Offset = " + str(int(dataOffset[0]) * 4) + " bytes\n"

        bits = ""
        if hexPairCount == 13:
            flags += dataOffset[1] + hexValue
            flags_final = "TCP: Flags = 0x" + flags + "\n"
            bits += "{0:012b}".format(int(hexValue, 16))
            urgentPointerStatus = "TCP: .... .." + bits[6] + ". .... = Urgent Pointer Status\n"
            ackStatus  = "TCP: .... ..." + bits[7] + " .... = Acknowledgement Status\n"
            pushStatus = "TCP: .... .... " + bits[8] + "... = Push Status\n"
            resetStatus = "TCP: .... .... ." + bits[9] + ".. = Reset Status\n"
            synStatus = "TCP: .... .... .." + bits[10] + ". = Syn Status\n"
            finStatus = "TCP: .... .... ..." + bits[11] + " = Fin Status\n"

        if hexPairCount >= 14 and hexPairCount <= 15:
            window += hexValue
        if hexPairCount == 15 and windowTCP == 0:
            window_final = "TCP: Window = " + str(int(window, 16)) + "\n"
            windowTCP = 1

        if hexPairCount >= 16 and hexPairCount <= 17:
            checksum += hexValue
        if hexPairCount == 17 and checksumTCP == 0:
            checksum_final = "TCP: Checksum = 0x" + checksum + "\n"
            checksumTCP = 1

        if hexPairCount >= 18 and hexPairCount <= 19:
            urgentPoint += hexValue
        if hexPairCount == 19 and urgentPointTCP == 0:
            urgentPoint_final = "TCP: Urgent Pointer = " + str(int(urgentPoint, 16)) + "\n"
            urgentPointTCP = 1

        if port in destPort or port in sourcePort:
            answer = "True"

    tcpString += sourcePort_final + destPort_final + seqNumber_final + ackNumber_final + dataOffset_final + flags_final + urgentPointerStatus + ackStatus + pushStatus + resetStatus + synStatus + finStatus + window_final + checksum_final + urgentPoint_final + "TCP: \n"
    return tcpString, answer

def icmpFunction(icmpStringTemp):
    icmpStringTemp = icmpStringTemp.split(" ")
    icmpString = "ICMP: ---- ICMP Header ---- \nICMP: \n"

    echo = ""
    code = ""
    checksum = ""

    echo_final = ""
    code_final = ""
    checksum_final = ""

    for hexPairCount in range(len(icmpStringTemp)):
        hexValue = icmpStringTemp[hexPairCount]

        if hexPairCount == 0:
            echo += hexValue[1]
            echo_final = "ICMP: Type = " + echo + " (Echo Request)\n"

        if hexPairCount == 1:
            code += hexValue
            code_final = "ICMP: Code = " + code + "\n"

        if hexPairCount == 2 or hexPairCount == 3:
            checksum += hexValue
        if hexPairCount == 3:
            checksum_final = "ICMP: Checksum = " + checksum

    icmpString += echo_final + code_final + checksum_final + "\nICMP: \n"
    return icmpString


def main():
    print("The Program Begins........")
    print("4 additional arguments (apart from program name required to run as per condition)")
    # total arguments
    n = len(sys.argv)

    fileName = sys.argv[2]

    if n == 5:
        arg1 = sys.argv[3]
        arg2 = sys.argv[4]

    # print(fileName)
    # print(arg1)
    # print(arg2)

    readInput = rdpcap(fileName)
    completeOutput = ""

    limitFlag = -1

    if arg1 == "-c":
        limitFlag = 0

    packetCount = 0
    for packet in readInput:
        answerToArgument = ""
        packetCount += 1

        tempPacketHexDump = hexdump(packet, True)
        completeOutput += tempPacketHexDump

        if limitFlag == 0:
            if packetCount > int(arg2):
                break

        packetSize, splitStringAtLine = getPacketSize(tempPacketHexDump)

        splitStringAtEverySpace = ""
        countOfBytes = 0
        hexPairCount = -1

        destinationEther = ""
        sourceEther = ""
        etherType = ""

        ip4 = False
        ip6 = False

        udp = False
        tcp = False
        icmp = False
        protocolFlag = False

        udpStringTemp = ""
        tcpStringTemp = ""
        icmpStringTemp = ""

        etherString = "ETHER: ---- Ether Header ----\nETHER:\n"

        ipString = "IP: ---- IP HEADER ----\nIP:\n"
        ipVersion = ""
        ipheaderLength = ""
        iptypeOfService = ""

        flow = 0
        payload = 0
        nextHeader = 0
        hopLimit = 0
        sourceAddr = 0
        destAddr = 0

        pairCheck = 0

        ipFlowLabel_Final = ""
        ipPayloadLength_Final = ""
        ipNextHeader_Final = ""
        ipHopLimit_Final = ""
        ipSourceAddr_Final = ""
        ipDestAddr_Final = ""

        totalLength4 = 0
        identification4 = 0
        fragmentOffset4 = 0
        headerChecksum4 = 0
        sourceAddr4 = 0
        destAddr4 = 0

        precedence_FINAL = ""
        delay_FINAL = ""
        throughput_FINAL = ""
        reliability_FINAL = ""
        ipTotalLength_FINAL = ""
        ipIdentification_FINAL = ""
        ipFlags_FINAL = ""
        ipfragmentOrNot_FINAL = ""
        iplastFragment_FINAL = ""
        ipfragmentOffset_FINAL = ""
        ipTTL_FINAL = ""
        ipProtocol_FINAL = ""
        ipHeaderChecksum_FINAL = ""
        ipSourceAddr_FINAL = ""
        ipDestAddr_FINAL = ""

        udpString = ""
        tcpString = ""
        icmpString = ""

        ipFlowLabel = ""
        ipPayloadLength = ""
        ipNextHeader = ""
        ipSourceAddr = ""
        ipDestAddr = ""

        ipTotalLength = ""
        ipIdentification = ""
        ipfragmentOffset = ""
        ipHeaderChecksum = ""

        for i in splitStringAtLine:
            temp = i.split(" ")
            splitStringAtEverySpace = [-1 for jj in range(16)]
            tempArray = temp[2:]

            for tt in range(len(tempArray)):
                if tt < 16:
                    splitStringAtEverySpace[tt] = tempArray[tt]
                else:
                    break

            # print(splitStringAtEverySpace)

            for hexValue in splitStringAtEverySpace:
                # print(hexValue)
                hexPairCount += 1

                if hexPairCount < 14:
                    if hexPairCount < 6:
                        destinationEther += hexValue + ":"
                    elif hexPairCount < 12:
                        sourceEther += hexValue + ":"
                    elif hexPairCount < 14:
                        etherType += hexValue

                if hexPairCount == 14:
                    if "0800" in etherType:
                        ip4 = True
                        etherType = "0800 (IP)"
                    elif "86DD" in etherType:
                        ip6 = True
                        etherType = "86DD (IP)"

                    sourceEther = sourceEther[:-1]
                    destinationEther = destinationEther[:-1]

                    etherString += "ETHER: Packet Size = " + str(packetSize) + " bytes\n"
                    etherString += "ETHER: Destination = " + destinationEther + ",\n"
                    etherString += "ETHER: Source = " + sourceEther + ",\n"
                    etherString += "ETHER: Ethertype = " + etherType + "\nETHER:"

                if ip6 is True:
                    if hexPairCount >= 14:  # and hexPairCount <= 53
                        ipVersion = "IP: Version = 6\n"
                        ipheaderLength = "IP: Header Length = 40 bytes\n"
                        iptypeOfService = "IP: Type of service = 0x00\n"

                        if hexPairCount >= 15 and hexPairCount <= 17:
                            ipFlowLabel += hexValue
                        if flow == 0 and hexPairCount == 17:
                            ipFlowLabel_Final = "IP: Flow Label " + ipFlowLabel + ",\n"
                            flow = 1

                        if hexPairCount >= 18 and hexPairCount <= 19:
                            ipPayloadLength += hexValue
                        if payload == 0 and hexPairCount == 19:
                            ipPayloadLength_Final = "IP: Payload Length " + str(int(ipPayloadLength, 16)) + " bytes,\n"
                            payload = 1

                        if hexPairCount == 20:
                            ipNextHeader += hexValue
                        if "11" in ipNextHeader and protocolFlag is False:
                            udp = True
                            tcp = False
                            icmp = False
                            protocolFlag = True
                        elif "06" in ipNextHeader and protocolFlag is False:
                            tcp = True
                            udp = False
                            icmp = False
                            protocolFlag = True
                        elif "01" in ipNextHeader and protocolFlag is False:
                            tcp = False
                            udp = False
                            icmp = True
                            protocolFlag = True
                        if nextHeader == 0 and hexPairCount == 20:
                            protocol = ""
                            if udp:
                                protocol = "17 (UDP)"
                            elif tcp:
                                protocol = "06 (TCP)"
                            elif icmp:
                                protocol = "01 (ICMP)"
                            ipNextHeader_Final = "IP: Protocol " + protocol + ",\n"
                            nextHeader = 1

                        ipHopLimit = ""
                        if hexPairCount == 21:
                            ipHopLimit += hexValue
                        if hopLimit == 0 and hexPairCount == 21:
                            ipHopLimit_Final = "IP: Hop Limit " + str(int(ipHopLimit, 16)) + ",\n"
                            hopLimit = 1

                        if hexPairCount >= 22 and hexPairCount <= 37:
                            if pairCheck == 0:
                                ipSourceAddr += hexValue
                                pairCheck = 1
                            elif pairCheck == 1:
                                ipSourceAddr += hexValue + ":"
                                pairCheck = 0
                        if sourceAddr == 0 and hexPairCount == 37:
                            ipSourceAddr_Final = "IP: Source Address: " + ipSourceAddr[:-1] + ",\n"
                            sourceAddr = 1

                        if hexPairCount >= 38 and hexPairCount <= 53:
                            if pairCheck == 0:
                                ipDestAddr += hexValue
                                pairCheck = 1
                            elif pairCheck == 1:
                                ipDestAddr += hexValue + ":"
                                pairCheck = 0
                        if destAddr == 0 and hexPairCount == 53:
                            ipDestAddr_Final = "IP: Destination Address: " + ipDestAddr[:-1] + ",\n"
                            destAddr = 1

                        if hexPairCount == 53:
                            ipString += ipVersion + ipheaderLength + iptypeOfService + ipFlowLabel_Final + ipPayloadLength_Final + ipNextHeader_Final + ipHopLimit_Final + ipSourceAddr_Final + ipDestAddr_Final + "IP:"

                        startProtocol = 54
                        # udp function
                        if udp is True:
                            if hexPairCount >= startProtocol and hexPairCount <= (startProtocol + 7):
                                udpStringTemp += hexValue + " "
                            if hexPairCount == (startProtocol + 7):
                                udpString, answer = udpFunction(udpStringTemp, arg2)

                        # same for tcp
                        if tcp is True:
                            if hexPairCount >= startProtocol and hexPairCount <= (startProtocol + 19):
                                tcpStringTemp += hexValue + " "
                            if hexPairCount == (startProtocol + 19):
                                tcpString, answer = tcpFunction(tcpStringTemp, arg2)

                        # same for icmp
                        if icmp is True:
                            if hexPairCount >= startProtocol and hexPairCount <= (startProtocol + 2):
                                icmpStringTemp += hexValue + " "
                            if hexPairCount == (startProtocol + 2):
                                icmpString = icmpFunction(icmpStringTemp)


                elif ip4 is True:
                    if hexPairCount >= 14:  # and hexPairCount <= 34
                        ipVersion = "IP: Version = 4\n"
                        ipheaderLength = "IP: Header Length = 20 bytes\n"
                        iptypeOfService = "IP: Type of service = 0x00\n"

                        # ipHeaderLength = ""
                        # if hexPairCount == 14:
                        #     ipHeaderLength += str(int(hexValue[1]) * 4) + " bytes"
                        # ipHeaderLength_Final = "IP: Header Length = " + ipHeaderLength + ",\n"

                        decimal = ""
                        bits = ""
                        precedence = ""
                        delay = ""
                        throughput = ""
                        reliability = ""
                        if hexPairCount == 15:
                            decimal += str(int(hexValue, 16))
                            bits += str("{0:08b}".format(int(hexValue, 16)))
                            precedence_FINAL = "IP: xxx. .... = " + str(int(bits[3:], 2)) + " (precedence)\n"
                            delay_FINAL = "IP: ..." + str(bits[3]) + " .... = delay\n"
                            throughput_FINAL = "IP: .... " + str(bits[4]) + "... = throughput\n"
                            reliability_FINAL = "IP: .... ." + str(bits[5]) + ".. = reliability\n"

                        if hexPairCount >= 16 and hexPairCount <= 17:
                            ipTotalLength += hexValue
                        if totalLength4 == 0 and hexPairCount == 17:
                            ipTotalLength_FINAL = "IP: Total Length = " + str(int(ipTotalLength, 16)) + " bytes,\n"
                            totalLength4 = 1

                        if hexPairCount >= 18 and hexPairCount <= 19:
                            ipIdentification += hexValue
                        if identification4 == 0 and hexPairCount == 19:
                            ipIdentification_FINAL = "IP: Identification = " + str(int(ipIdentification, 16)) + "\n"
                            identification4 = 1

                        ipFlags = ""
                        bits = ""
                        if hexPairCount == 20:
                            bits += str("{0:08b}".format(int(hexValue, 16)))
                            swapBytes = bits[4:] + bits[0:4]
                            ipFlags_FINAL = "IP: Flags = 0x" + str(int(swapBytes[0:3], 2)) + "\n"
                            ipfragmentOrNot_FINAL = "IP: ." + swapBytes[1] + ".. .... = " + (
                                "fragment\n" if swapBytes[1] == 0 else "do not fragment\n")
                            iplastFragment_FINAL = "IP: .." + swapBytes[2] + ". .... = last fragment\n"

                        bits = ""
                        if hexPairCount == 20 or hexPairCount == 21:
                            ipfragmentOffset += hexValue
                        if hexPairCount == 21 and fragmentOffset4 == 0:
                            bits += str("{0:016b}".format(int(ipfragmentOffset, 16)))
                            ipfragmentOffset_FINAL = "IP: Fragment offset = " + str(int(bits[3:], 2)) + " bytes\n"
                            fragmentOffset4 = 1

                        ipTTL = ""
                        if hexPairCount == 22:
                            ipTTL += hexValue
                            ipTTL_FINAL = "IP: Time to live = " + str(int(ipTTL, 16)) + " seconds\n"

                        ipProtocol = ""
                        if hexPairCount == 23:
                            ipProtocol += hexValue
                        if "11" in ipProtocol and protocolFlag is False:
                            udp = True
                            tcp = False
                            icmp = False
                            protocolFlag = True
                        elif "06" in ipProtocol and protocolFlag is False:
                            tcp = True
                            udp = False
                            icmp = False
                            protocolFlag = True
                        elif "01" in ipProtocol and protocolFlag is False:
                            tcp = False
                            udp = False
                            icmp = True
                            protocolFlag = True
                        if hexPairCount == 23:
                            protocol = ""
                            if udp:
                                protocol = "17 (UDP)"
                            elif tcp:
                                protocol = "06 (TCP)"
                            elif icmp:
                                protocol = "01 (ICMP)"
                            ipProtocol_FINAL = "IP: Protocol " + protocol + ",\n"

                        if hexPairCount >= 24 and hexPairCount <= 25:
                            ipHeaderChecksum += hexValue
                        if headerChecksum4 == 0 and hexPairCount == 25:
                            ipHeaderChecksum_FINAL = "IP: Header checksum = " + ipHeaderChecksum + "\n"
                            headerChecksum4 = 1

                        if hexPairCount >= 26 and hexPairCount <= 29:
                            if pairCheck == 0:
                                ipSourceAddr += str(int(hexValue, 16)) + "."
                                pairCheck = 1
                            elif pairCheck == 1:
                                ipSourceAddr += str(int(hexValue, 16)) + "."
                                pairCheck = 0
                        if sourceAddr4 == 0 and hexPairCount == 29:
                            ipSourceAddr_FINAL = "IP: Source Address: " + ipSourceAddr[:-1] + ",\n"
                            sourceAddr4 = 1

                        if hexPairCount >= 30 and hexPairCount <= 33:
                            if pairCheck == 0:
                                ipDestAddr += str(int(hexValue, 16)) + "."
                                pairCheck = 1
                            elif pairCheck == 1:
                                ipDestAddr += str(int(hexValue, 16)) + "."
                                pairCheck = 0
                        if destAddr4 == 0 and hexPairCount == 33:
                            ipDestAddr_FINAL = "IP: Destination Address: " + ipDestAddr[:-1] + ",\n"
                            destAddr4 = 1

                        if hexPairCount == 33:
                            ipString += ipVersion + ipheaderLength + iptypeOfService + precedence_FINAL + delay_FINAL + throughput_FINAL + reliability_FINAL + ipTotalLength_FINAL + ipIdentification_FINAL + ipFlags_FINAL + ipfragmentOrNot_FINAL + iplastFragment_FINAL + ipfragmentOffset_FINAL + ipTTL_FINAL + ipProtocol_FINAL + ipHeaderChecksum_FINAL + ipSourceAddr_FINAL + ipDestAddr_FINAL + "IP:"

                        # protocol functionality
                        startProtocol = 34
                        # udp function
                        if udp is True:
                            if hexPairCount >= startProtocol and hexPairCount <= (startProtocol + 7):
                                udpStringTemp += hexValue + " "
                            if hexPairCount == (startProtocol + 7):
                                udpString, answer = udpFunction(udpStringTemp, arg2)

                        # same for tcp
                        if tcp is True:
                            if hexPairCount >= startProtocol and hexPairCount <= (startProtocol + 19):
                                tcpStringTemp += hexValue + " "
                            if hexPairCount == (startProtocol + 19):
                                tcpString, answer = tcpFunction(tcpStringTemp, arg2)

                        # same for icmp
                        if icmp is True:
                            if hexPairCount >= startProtocol and hexPairCount <= (startProtocol + 2):
                                icmpStringTemp += hexValue + " "
                            if hexPairCount == (startProtocol + 2):
                                icmpString = icmpFunction(icmpStringTemp)

                # hexPairCount += 1
                if (arg1 == "host" or arg1 == "net") and (answerToArgument == "False" or answerToArgument == ""):
                    if arg2 in ipSourceAddr or arg2 in ipDestAddr:
                        answerToArgument = "True"
                    else:
                        answerToArgument = "False"

                if arg1 == "port" and (answerToArgument == "False" or answerToArgument == ""):
                    if answer == "True":
                        answerToArgument = "True"
                    else:
                        answerToArgument = "False"

        # print(etherString)
        print("Answer To Argument for the packet = " + answerToArgument)
        print(etherString)
        print(ipString)
        if udp:
            print(udpString)
        if tcp:
            print(tcpString)
        if icmp:
            print(icmpString)

        # completeOutput += "\n\n"

        # print()
        # print("-----------------")
        # print()
    # print(completeOutput)

main()