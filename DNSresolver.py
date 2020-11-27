#!/usr/bin/env python

import socket
import struct
import sys
import argparse

def struct_packer(name, type):
    """Returns a DNS query header, according to standards specified in RFC 2929, for a given hostname."""

    packed_header = struct.pack("!HHHHHH", 550, 0, 1, 0, 0, 0)

    #split the domain name into its subdomains
    subdomains = name.split('.')
    if subdomains[-1] == '': subdomains.pop() #remove extra dot if needed
    formated_name = ""
    for word in subdomains:
        formated_name += struct.pack("!B", len(word)) + word
    formated_name += struct.pack("!B", 0)

    if(type): #If we are querying for a mail record
        packed_QTYPE = struct.pack("!H", 15)
    else:
        packed_QTYPE = struct.pack("!H", 1)

    packed_question = formated_name + packed_QTYPE + struct.pack("!H", 1)
    DNS_query = packed_header + packed_question
    
    return DNS_query

class Record:
    def __init__(self, Name, Type, Rdata):
        self.Name = Name
        self.Type = Type
        self.Rdata = Rdata

def read_name(index, buffer):
    """Returns a dynamic length name section from a DNS resource record starting from a given index"""

    if (buffer[index] == '\0'):
        return ("", index + 1)
    else:
        first_byte = ord(buffer[index])
        if ((first_byte & (1<<7)) > 0 and (first_byte & (1<<6)) > 0):
            new_index, = struct.unpack("!H", buffer[index:index+2])
            new_index = new_index - (1<<15) - (1<<14)
            (Name, _) = read_name(new_index, buffer)
            return (Name, index + 2)
        else:
            Name = ""
            for i in range(first_byte):
                index += 1
                Name += buffer[index]
            Name += "."
            index += 1
            (almost_name, final_idex) = read_name(index, buffer)
            return (Name + almost_name, final_idex)

def parse_record(index, buffer):
    """Returns a Record object storing the Name, Type, and RData fields of a DNS resource record"""

    (Name,index) = read_name(index, buffer)

    Type, = struct.unpack("!H", buffer[index:index+2])
    index += 8

    RDlength, = struct.unpack("!H", buffer[index:index+2])
    index += 2

    #NS -> value is name
    #A  -> value is IP
    #MX 
    Rdata = ""
    if Type == 1: #A
        a1, a2, a3, a4 = struct.unpack("!BBBB", buffer[index:index+4])
        Rdata = "%s.%s.%s.%s" % (str(a1), str(a2), str(a3), str(a4))
    elif Type == 2: #NS
        (name, _) = read_name(index, buffer)
        Rdata = name
    elif Type == 15: #MX
        (name, _) = read_name(index+2, buffer)
        Rdata = name
    else: #TODO: Add support for SOA
        Rdata = None

    index += RDlength

    record = Record(Name, Type, Rdata)
    return record, index

def query_server(socket, server, host_name, type):
    """Primary function which will query a given hostname and compile a list of all resource records pointing to the next location to query"""

    DNS_query = struct_packer(host_name, type)
    socket.sendto(DNS_query, (server, 53))

    query_response, _ = socket.recvfrom(4096)
    
    ID, flags, QDcount, ANcount, NScount, ARcount = struct.unpack('!HHHHHH', query_response[0:12])

    name_end = query_response.find('\0', 12) + 5
    index = name_end



    ANrecord_list = []
    for i in range(ANcount):
        (record, index) = parse_record(index, query_response)
        if record.Rdata is not None: ANrecord_list.append(record)

    NSrecord_list = []
    for i in range(NScount):
        (record, index) = parse_record(index, query_response)
        if record.Rdata is not None: NSrecord_list.append(record)
        if NScount == 1 and ANcount == 0 and ARcount == 0 and record.Rdata is None:
            print("Error: Found SOA record, DNS query failed")
            exit(0)


    ARrecord_list = []
    for i in range(ARcount):
        (record, index) = parse_record(index, query_response)
        if record.Rdata is not None: ARrecord_list.append(record)

    if len(ANrecord_list) > 0:
        return ANrecord_list[0].Rdata
    else:
        new_servers = []
        for i in NSrecord_list:
            ip = None
            for j in ARrecord_list:
                if j.Type == 1 and j.Name == i.Rdata:
                    ip = j.Rdata
                    break
            if ip is not None:
                new_servers.append((i.Rdata, ip))
        return query_server_list(socket, new_servers, host_name, type)

def query_server_list(sock, server_list, host_name, type):
    """Conducts a DNS query for all servers in the given list until it resolves the hostname to an IP address"""

    for (name, ip) in server_list:
        try:
            print("Querying %s (%s) to look up %s (MX: %r)" % (ip,name,host_name,type))
            res = query_server(sock, ip, host_name, type)
            return res
        except socket.timeout:
            print("IP %s timed out" % ip)

def main(arguments):
    parser = argparse.ArgumentParser(description="DNS resolution")
    parser.add_argument("-m", action="store_true")
    parser.add_argument("hostname")
    args = parser.parse_args()
    is_mail = args.m
    hostname = args.hostname
    # print 'I received the following arguments:', arguments
    print("Input: hostname = %s, querying mail server = %r" % (hostname, is_mail))
    # read in the root servers to send to iterative resolver.
    with open("root-servers.txt", "r") as file:
        root_servers = file.read().splitlines()

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5)

    root_servers = map(lambda x: ("root server",x), root_servers)
    
    if not is_mail:
        res = query_server_list(s, root_servers, hostname, is_mail)
        print("The name %s resolves to %s" % (hostname, res))
    else:
        mailName = query_server_list(s, root_servers, hostname, is_mail)
        print("MX answer: %s" % (mailName))
        res = query_server_list(s, root_servers, mailName, False)
        print("Answer: %s resolves to %s" % (hostname, res))

if __name__ == '__main__':
    main(sys.argv)
