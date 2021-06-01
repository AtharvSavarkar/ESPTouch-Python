import socket
import threading
import time

ipBytes = None
ssidBytes = None
bssidBytes = None
passwordBytes = None
data = None
dataToSend = []

addressCount = 0
useBroadcast = False
sendBuffer = bytearray(600)


def getClientSocket():
    global useBroadcast
    sock = socket.socket(socket.AF_INET,  # Internet
                         socket.SOCK_DGRAM)  # UDP

    # sock is a socket which can generated using 2 arguments
    # 1. socket.AF_INET  --  This is like a (host, port) tuple (not exactly a tuple) -- host can be in form of domain ('www.google.com') or ip address (192.168.1.1) -- port is a integer
    # 2. socket.SOCK_DGRAM -- is the protocol used for communication (in this case UDP) -- socket.SOCK_STREAM for TCP

    if useBroadcast:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    # not_clear

    return sock


def sendPacket(_socket, _destination, _size):
    # _socket is a socket as explained earlier
    # _destination is a (host, port) tuple -- e.g. ('192.168.1.1', 8032)
    # _size is integer -- not_clear

    if isinstance(_socket, socket.socket) is not True:  # "is not True" is replaced by "is False" #change
        raise ValueError("sendPacket error invalid socket object")

    # The isinstance() function returns True if the specified object is of the specified type, otherwise False
    # If there is some error in defining socket ValueError will be raised

    global sendBuffer
    #    print("{}  Sending {} bytes to {}".format(time.monotonic(), len(sendBuffer[0:_size]), _destination))
    _socket.sendto(sendBuffer[0:_size], _destination)

    # exact working of socket.sendto not_clear

    # sendBuffer[0:_size] is same as bytearray(_size)


def getNextTargetAddress():
    global useBroadcast
    global addressCount

    # if broadcast is kept true then get is always return ("255.255.255.255", 7001)

    if useBroadcast:
        return ("255.255.255.255", 7001)
    else:

        # this part is for multicast - will not run if broadcast is true

        addressCount += 1
        multicastAddress = "234.{}.{}.{}".format(addressCount, addressCount, addressCount)
        addressCount %= 100
        return (multicastAddress, 7001)


# Following is cyclic redundancy check function - checks if there is any error in sending/receiving data using a CRC code
def AddToCRC(b, crc):
    if (b < 0):
        b += 256
    for i in range(8):

        # (((^ does bitwise XOR operation between b and crc) bitwise and with 1) == 1) then odd is True

        odd = ((b ^ crc) & 1) == 1
        crc >>= 1
        b >>= 1
        if (odd):
            crc ^= 0x8C  # this means crc ^= 140
    return crc


# one data format:(data code should have 2 to 65 data)
# 
#              control byte       high 4 bits    low 4 bits
# 1st 9bits:       0x0             crc(high)      data(high)
# 2nd 9bits:       0x1                sequence header
# 3rd 9bits:       0x0             crc(low)       data(low)
# 
# some complex encoding function
def encodeDataByte(dataByte, sequenceHeader):
    if sequenceHeader > 127:
        raise ValueError('sequenceHeader must be between 0 and 127')
    # calculate the crc
    crc = 0
    crc = AddToCRC(dataByte, crc)
    crc = AddToCRC(sequenceHeader, crc)

    # split in nibbles
    crc_high, crc_low = crc >> 4, crc & 0x0F
    data_high, data_low = bytes([dataByte])[0] >> 4, bytes([dataByte])[0] & 0x0F

    # reassemble high with high , low with low and add 40
    first = ((crc_high << 4) | data_high) + 40
    # second ninth bit must be set (256 + 40)
    second = 296 + sequenceHeader
    third = ((crc_low << 4) | data_low) + 40

    return (first, second, third)


def getGuideCode():
    return (515, 514, 513, 512)


def getDatumCode():
    global ssidBytes
    global bssidBytes
    global passwordBytes
    global data

    totalDataLength = 5 + len(
        data)  # len(data) is total length of data (ssid, password, ip) if appended in ome string (bssid is not included in this)
    # 5 is added to len(data) as (totalDataLength, passwordLength, ssidCrc, bssidCrc, totalXor) will be added with data before sending

    passwordLength = len(passwordBytes)  # passwordLength is equal to len(password) (length of password as a string)

    ssidCrc = 0
    for b in ssidBytes:
        ssidCrc = AddToCRC(b, ssidCrc)

    bssidCrc = 0
    for b in bssidBytes:
        bssidCrc = AddToCRC(b, bssidCrc)

    totalXor = 0
    totalXor ^= totalDataLength
    totalXor ^= passwordLength
    totalXor ^= ssidCrc
    totalXor ^= bssidCrc

    for b in data:
        totalXor ^= b

    return (totalDataLength, passwordLength, ssidCrc, bssidCrc, totalXor)


def getDataCode():
    return (data)


def prepareDataToSend():
    global dataToSend
    global bssidBytes

    # human readable data in the console in pack of three bytes
    #    i = 0
    #    for b in getDatumCode():
    #        print(encodeDataByte(b, i))
    #        i += 1
    #
    #    iBssid = len(getDatumCode()) + len(getDataCode())
    #    bssidLength = len(bssidBytes)
    #    indexBssid = 0
    #    indexData = 0
    #    for b in getDataCode():
    #        # add a byte of the bssid every 4 bytes
    #        if (indexData % 4) == 0 and indexBssid < bssidLength:
    #            print(encodeDataByte(bssidBytes[indexBssid], iBssid))
    #            iBssid += 1
    #            indexBssid += 1
    #        print(encodeDataByte(b, i))
    #        i += 1
    #        indexData += 1
    #    while indexBssid < bssidLength:
    #        print(encodeDataByte(bssidBytes[indexBssid], iBssid))
    #        iBssid += 1
    #        indexBssid += 1

    # The data
    i = 0
    for d in getDatumCode():  # getDatumCode() returns (totalDataLength, passwordLength, ssidCrc, bssidCrc, totalXor)
        for b in encodeDataByte(d, i):  # encodeDataByte(dataByte, sequenceHeader) returns (first, second, third)
            dataToSend += [b]
        i += 1

    iBssid = len(getDatumCode()) + len(
        getDataCode())  # getDataCode() function returns data (which is ip + ssid + password in bytearray format)

    bssidLength = len(bssidBytes)  # Gives length of bssid

    indexBssid = 0
    indexData = 0
    for d in getDataCode():
        # add a byte of the bssid every 4 bytes
        if (indexData % 4) == 0 and indexBssid < bssidLength:
            for b in encodeDataByte(bssidBytes[indexBssid], iBssid):
                dataToSend += [b]
            iBssid += 1
            indexBssid += 1
        for b in encodeDataByte(d, i):
            dataToSend += [b]
        i += 1
        indexData += 1
    while indexBssid < bssidLength:
        for b in encodeDataByte(bssidBytes[indexBssid], iBssid):
            dataToSend += [b]
        iBssid += 1
        indexBssid += 1


def sendGuideCode():
    index = 0
    destination = getNextTargetAddress()

    # run for 2 sec send packet every 8 msec

    nexttime = now = time.monotonic()  # time.monotonic() gives time as a float number - which increases with time
    endtime = now + 2  # This can be changed to change time for which transmission occurs
    while now < endtime or index != 0:
        now = time.monotonic()
        if now > nexttime:
            sendPacket(getClientSocket(), destination,
                       getGuideCode()[index])  # getClientSocket() gives same socket for broadcast
            # destination remains same for broadcast
            # getGuideCode() is a array (515, 514, 513, 512)
            nexttime = now + 0.008
            index += 1
            if index > 3:
                destination = getNextTargetAddress()
            index %= 4


def sendDataCode():
    global dataToSend

    index = 0
    destination = getNextTargetAddress()  # if Broadcast is kept on data will be transmitted at 255.255.255.255
    # run for 4 sec send packet every 8 msec
    nexttime = now = time.monotonic()
    endtime = now + 4
    while now < endtime or index != 0:
        now = time.monotonic()
        if now > nexttime:
            sendPacket(getClientSocket(), destination, dataToSend[index])
            nexttime = now + 0.008
            index += 1
            if (index % 3) == 0:
                destination = getNextTargetAddress()
            index %= len(dataToSend)


def sendData():
    # print("DATUM: ", getDatumCode())
    # print("GUIDE: ", getGuideCode())

    prepareDataToSend()  # Encodes data
    print("Sending data...")
    for i in range(5):  # Number of iterations of sending data can be increases for higher probability of connecting

        # sendGuideCode() runs for 2 secs and transmits every 8 milisecs
        sendGuideCode()

        # sendDataCode() runs for 4 secs and transmits every 8 milisecs
        sendDataCode()

        # Total time for which transmission will be on = (2 + 4)*(number of loops)


def init(_ssid, _password, _broadcast, _ip, _bssid):
    global ssidBytes
    global ipBytes
    global bssidBytes
    global passwordBytes
    global useBroadcast
    global data

    if _bssid:
        # This returns number of bytes in BSSID of router (in form of a bytearray)
        bssidBytes = bytes.fromhex(_bssid)
    else:
        # this will run if bssid of router is not provided - bytes(a) will return immutable bytearray with a elements - in this case 0 elements
        bssidBytes = bytes()

    ssidBytes = bytes(_ssid.encode())  # This will encode SSID in bytes
    passwordBytes = bytes(_password.encode())  # This will encode password in bytes
    ipBytes = bytes(map(int, _ip.split(
        '.')))  # This will encode ip of router in bytes - length of this will always be 4 (as ip is like 192.168.1.1 - 4 segments)

    useBroadcast = _broadcast[0] == 'T' or _broadcast[
        0] == 't'  # value of useBroadcast will be True or false depending on command given

    if len(ipBytes) != 4:  # This will ensure IP is of 4 bytes
        raise ValueError("IP address invalid")

    # This Data segment in UDP packet
    data = ipBytes + passwordBytes

    # + ssid if hidden but this is not enforced on Android..... so we always include it as well
    data += ssidBytes

    # Data is ip (4 bytes) + password + ssid (all in byte format)


#    print("DATA length", len(data))
#    print("DATA-->", ":".join("{:02x}".format(c) for c in data))
#    print("bssid-->", ":".join("{:02x}".format(c) for c in bssidBytes))
#    print("ssid-->", ":".join("{:02x}".format(c) for c in ssidBytes))
#    print("Broadcast--> {}".format(useBroadcast))


receive_ip = "0.0.0.0"
receive_port = 18266


def receive():
    ip = "0.0.0.0"  # ip = 0.0.0.0 means it will receive from every ip that is transmitting on given port (as ip address of chip will be unknown)
    # similar analogy to Matlab UDP receiver object - dsp.UDPReceiver
    # multiple (different) packets can be received if multiple devices are simultaneously transmitting on 18266 port

    port = 18266  # 18266 is port on which ESP8266 transmits data
    # Got to know from ESPTouch Source Code for Android - TargetPort is 7001 (receiving port for ESP8266) and ListeningPort is 18226 (transmitting port of ESP8266)
    # ESP8266 receives signals on 7001 port (if port is set to 7001 then transmitted signal will be received back)
    # IMPORTANT - Don't try to run any other software in parallel to receive on this port as this will lead to error

    # Create a UDP socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # socket.AF_INET is like a tuple of (host, port) #not_sure
    # socket.SOCK_DGRAM defined UDP communication protocol (sock.SOCK_STREAM for TCP)

    # Bind the socket to the port
    server_address = (ip, port)
    s.bind(server_address)

    print('Receiver running...')
    print()

    data_array = []
    address_array = []

    socket_timeout = 60
    s.settimeout(socket_timeout)

    for i in range(5):

        data, address = s.recvfrom(4096)

        data_array.append(data)
        address_array.append(address)

    if (len(set(data_array)) == 1):
        if (len(set(address_array)) == 1):
            print('Data Received from ESP8266')
            print()

    # Data array obtained from chip consist of 11 elements
    # First element denotes size of data provided (ssid + password + ip + bssid + ....)
    # Next 6 elements is MAC ID of the chip (convert it to hex using hex() to get MAC ID)
    # Last 4 elements is IP Address of the chip

    mac_id = ''
    for i in range(7)[1::]:
        if len(hex(data[i])) == 3:
            mac_id += '0' + hex(data[i])[-1]
        if len(hex(data[i])) == 4:
            mac_id += hex(data[i])[-2::]

    print("MAC ID of Chip is -", mac_id)
    print("IP Address of Chip is - {}.{}.{}.{}".format(data[-4], data[-3], data[-2], data[-1]))

    return mac_id


def ESPTouch(wifi_ssid, wifi_password):
    # Change variables related to wifi from here
    ssid = wifi_ssid

    password = wifi_password

    broadcast_status = "T"

    # This is optional parameter
    # Router IP address can be found using "ipconfig /all" in cmd (search in wifi adapter section)
    # If router IP unknown then keep "router_ip = 0.0.0.0"
    router_ip = "0.0.0.0"

    # This is an optional parameter
    # Can be found by command "netsh wlan show interfaces" in cmd
    # If BSSID of router is unknown then keep "router_bssid = None"
    # Remove colons from BSSID e.g. if BSSID = b8:c1:ac:a6:35:93 then keep "router_bssid = "b8c1aca63593""
    router_bssid = None

    init(ssid, password, broadcast_status, router_ip, router_bssid)
    # Threading is used as sending and receiving data should start simultaneously
    threading.Thread(target=sendData).start()

    # Receive function is kept in try as it returns timeout error after some duration (as set in receive function)
    try:
        mac_id = receive()
    # except will run only if socket encounters timeout (otherwise error will be printed)
    except socket.timeout:
        print('Did not receive anything')
        return -1
        pass

    return mac_id
