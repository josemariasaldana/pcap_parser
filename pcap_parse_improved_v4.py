#!/usr/bin/python3
# 
# adapted by Jose Saldana, May 2021, from an original
# script by David Chidell (dchidell)
# see https://github.com/dchidell/pcap_parser

#################################
# Script that compares two .pcap files looking for lost packets. It creates an .xlsx file reporting the additional delay caused by packet loss.
#################################
# The following is performed as a result of this script:
# * 2 PCAP Files opened and read
# * Summary statistics output to stdout
# * An excel file created containing one row per IP packet in the first pcap file, and info about lost packets.
##################################
# Requirements:
# * 'xlsxwriter', 'argparse', 'dpkt', 'binascii' python packages. ALl of these can be installed using pip
# * File read & write access to the current directory
# * A rather large amount of memory for large pcap files!
##################################
# Notes:
# Takes a long time for large pcap files ~30 seconds per GB on my mac + file save time - larger CPU will assist this.
##################################

# usage example
# ~/pcap_parser$ ./pcap_parse_improved_v3.py ../tm-eth0.pcap ../tm-eth0-3missing.pcap tm-eth0.xlsx
# where
# - tm-eth0.pcap is the origin pcap file (no lost packets)
# - tm-eth0-3missing.pcap is the pcap file at the destination (lost packets)
# - th-eth0.xlsx is the output file where the results wil be reported. You will have the
#   length of each burst, and the additional delay caused by each loss burst, measured
#   as the difference between the original timestamp of the first received packet after the burst
#   minus the original timestamp of the first lost packet of the burst
#
#   1   t=1.0       Arrived
#   2   t=3.0       Arrived
#   3   t=6.0       Lost
#   4   t=10.0      Lost
#   5   t=11.0      Arrived
#
#   this will be the result:
#   nr  timestamp           Arrived       acum burst  added delay burst size
#   1   1.0         ...     1           0           0           0
#   2   3.0         ...     1           0           0           0
#   3   6.0         ...     0           1           0           0
#   4   10.0        ...     0           2           0           0
#   5   11.0        ...     1           0           5.0         2       <-  the two last columns are only added after a burst
#                                                                           5.0 = 11.0 - 6.0 

ETH_TYPE_GOOSE = 0x88b8  # IEC 61850 GOOSE

import xlsxwriter
import argparse
import dpkt
import binascii
import sys
    
def parse_args():
    parser = argparse.ArgumentParser(
        description='Processes a PCAP file and converts packets to excel rows for further analysis.',
        epilog='Written by David Chidell (dchidell@cisco.com)')
    parser.add_argument('pcap1', metavar='capture.pcap',
                        help='This is the first pcap file containing the capture we wish to parse')
    parser.add_argument('pcap2', metavar='capture.pcap',
                        help='This is the second pcap file containing the capture we wish to parse')
    parser.add_argument('outfile', metavar='capture.xlsx',
                        help='This is the excel file we wish to export.')
    return parser.parse_args()

def raw_mac_to_string(mac_addr):
    mac_hex = binascii.hexlify(mac_addr)
    str_list = list()
    for i in range(6):
        str_list.append(mac_hex[i*2:i*2+2].decode('utf-8'))
    human_mac = ":".join(str_list)
    return human_mac

def raw_ip_to_string(ip_addr):
    ip_hex = binascii.hexlify(ip_addr)
    str_list = list()
    for i in range(4):
        hex_octet_string = ip_hex[i*2:i*2+2].decode('utf-8')
        dec_octet_int = int(hex_octet_string,16)
        str_list.append(str(dec_octet_int))
    human_ip = ".".join(str_list)
    return human_ip

def write_excel_row(sheet,row,data):
    for col,entry in enumerate(data):
        sheet.write(row,col,entry)

def progress(count, total, status=''):
    bar_len = 80
    filled_len = int(round(bar_len * count / float(total)))

    percents = round(100.0 * count / float(total), 1)
    bar = '=' * (filled_len-1) + '>' + '-' * (bar_len - filled_len)

    sys.stdout.write('[%s] %s%s ...%s\r' % (bar, percents, '%', status))
    sys.stdout.flush()

def main():
    args = parse_args()
    filename = args.outfile if '.xlsx' in args.outfile else args.outfile+'.xlsx'

    workbook = xlsxwriter.Workbook(filename)
    sheet = workbook.add_worksheet()
    write_excel_row(sheet,0,['PKT NUMBER','TIMESTAMP','VLAN','ETH SIZE','Arrived','acum burst size', 'added delay', 'burst size', 'GOOSE_time_allowed_to_live', 'GOOSE_stNum', 'bool1', 'bool2'])

    first_ts = -1
    last_ts = -1
    packet_count1 = 0
    packet_count2 = 0
    lost_packets = 0

    lost_burst_size = 0

    ip_count = 0
    vlan_dict = {}
    srcip_dict = {}
    dstip_dict = {}
    packet_sizes = []
    
    print('*** Processing packets and writing excel. This can take a while if you have large pcap files')
    print('Counting packets...')

    for ts, packet in dpkt.pcap.Reader(open(args.pcap1,'rb')):
        packet_count1 += 1
    print('Found {} packets in the first pcap file'.format(packet_count1))

    for ts, packet in dpkt.pcap.Reader(open(args.pcap2,'rb')):
        packet_count2 += 1
    print('Found {} packets in the second pcap file'.format(packet_count2))

    if packet_count1 < packet_count2:
        print('WARNING: the idea is that {} has all the packets and some of them are missing in {}'.format(args.pcap1,args.pcap2))
        print('HOWEVER, {} has less packets than {}. ({}<{})'.format(args.pcap1,args.pcap2,packet_count1,packet_count2))

    current_packet = 0
    current_percent = 0
    current_packet2 = 0
    current_percent2 = 0

    timestamp_first_lost_packet = 0.0

    # example of the program structure from
    # https://stackoverflow.com/questions/45243904/find-missing-lines-by-comparing-two-file-using-python-re-module/45244027

    for ts, packet in dpkt.pcap.Reader(open(args.pcap1,'rb')):
        current_packet += 1
        percent_done = round((current_packet / packet_count1)*100)
        if percent_done != current_percent:
            current_percent = percent_done
            progress(current_packet, packet_count1, status=' Processing PCAP 1')

        if 0:
            print('timestamp packet #{}: '.format(ts))

        try:
            eth = dpkt.ethernet.Ethernet(packet)
        except dpkt.dpkt.NeedData:
            print('Error Handling Packet Number: {} from trace 1'.format(current_packet))
            continue

        for ts2, packet2 in dpkt.pcap.Reader(open(args.pcap2,'rb')):
            current_packet2 += 1
            packet_found = 0

            percent_done2 = round((current_packet2 / packet_count2)*100)
            if percent_done2 != current_percent2:
                current_percent2 = percent_done2
                #progress(current_packet2, packet_count2, status=' Processing PCAP 2')

            if 0:
                print('file 1 #{}. file 2 #{}'.format(current_packet,current_packet2))

            try:
                eth2 = dpkt.ethernet.Ethernet(packet2)
            except dpkt.dpkt.NeedData:
                print('Error Handling Packet Number: {} from trace 2'.format(current_packet2))
                continue

            # this works properly:
            if 0:
                print('eth  {}'.format(eth))
                print('eth2 {}'.format(eth))
                print('s1 == s2: {}'.format(str(eth) == str(eth2)))

            # 'str(eth)' converts the packet to a string
            if str(eth) == str(eth2):
                # the two packets are equal. I have found the packet in the second trace
                packet_found = 1
                print('Packet #{} from trace 1 found in position #{} of trace 2'.format(current_packet, current_packet2))
                break

        if packet_found == 0:
            #lost_burst_size += 1
            lost_packets += 1
            print('Packet #{} of trace 1 not found in trace 2'.format(current_packet))

        # store the missing packet in an Excel file

        # check the type. If it is IP, then increase the IP counter
        # not needed so far, but I keep it here just in case
        if eth.type!=dpkt.ethernet.ETH_TYPE_IP:
            ip_count += 1
        if first_ts == -1:
            first_ts = ts

        # variable that will store a row for the Excel file
        excel_entry = []

        # add Excel column #1 with the number of the packet in trace 1
        excel_entry.append(current_packet)

        # add Excel column #2 with the timestamp
        excel_entry.append(ts-first_ts)

        # add Excel column #3 with the VLAN tag
        # not needed so far, but I keep it here just in case
        if hasattr(eth,'tag'):
            excel_entry.append(eth.tag)
            if eth.tag in vlan_dict:
                vlan_dict[eth.tag] += 1
            else: vlan_dict[eth.tag] = 1
        else:
            excel_entry.append('None')

        # add column #4 with the ethernet size
        #packet_sizes.append(eth.__len__()) #eth.__len__()
        excel_entry.append(eth.__len__())

        # add Excel column 5: 'Lost' or 'Arrived'
        # add Excel column 6: acum burst size
        if packet_found == 0:
            # the packet is lost
            # add the vaule '0' in the 'Arrived' column
            excel_entry.append(0)
            # add the acum size of the burst of lost packets
            excel_entry.append(lost_burst_size + 1)
        else:
            # the packet has arrived correctly
            # add the vaule '1' in the 'Arrived' column
            excel_entry.append(1)
            # the acum size of the burst of lost packets is 0
            excel_entry.append(0)

        # add Excel column 7: delay caused by a burst of lost packets
        # add Excel column 8: accumulated number of packets in a burst of lost packets
        #                       it is only added if the arrived packet ends a burst of lost packets
        #                       otherwise it is 0
        #if lost_burst_size > 0 and packet_found == 1:
        if lost_burst_size > 0:
            # obtained as the current timestamp - the timestamp of the first lost packet
            excel_entry.append(ts-timestamp_first_lost_packet)
            excel_entry.append(lost_burst_size)
        else:
            excel_entry.append(0)
            excel_entry.append(0)

        # add Excel column 9: if the packet is GOOSE, store "time_allowed_to_live"
        # check if the type is GOOSE
        # not needed so far, but I keep it here just in case
        if eth.type==ETH_TYPE_GOOSE:
            # Unpack the Ethernet frame (mac src/dst, ethertype)
            eth = dpkt.ethernet.Ethernet(packet)
            #print ('Ethernet Frame: {} {} {}'.format(eth.dst, eth.src, eth.type))

            # Now unpack the data within the Ethernet frame (GOOSE)
            goose = eth.data

            # The size of the 'time allowed to live' is in byte 52
            size_tal = goose[52]
            if 0:
                print(size_tal)

            if size_tal == 1:
                # if it is '1', then the value is in byte 53
                time_allowed = goose[53]
            else:
                if size_tal == 2:
                    # if it is '2', then the value is in bytes 53 and 54
                    time_allowed = goose[53]*256 + goose[54]
                else:
                    print ('error')
                    continue

            # add the value to the column
            excel_entry.append(time_allowed)
            if 0:
                print(time_allowed)


            # the position of 'stNum' depends on the size of time_allowed_to_live
            size_stnum = goose[114 + size_tal - 1]
            if 0:
                print(size_stnum)

            # fill the column 'stNum'
            if size_stnum == 1:
                stnum = goose[114 + size_tal]
            else:
                if size_stnum == 2:
                    stnum = goose[114 + size_tal]*256 + goose[115 + size_tal]
                else:
                    print('error')
                    continue

            # add the value to the column
            excel_entry.append(stnum)
            if 0:
                print(stnum)


            # I use 'offset' to take into account the variable length of two fields
            #'time_allowed_to_live' and 'stNum'
            # If their size is not '1', all the values are moved 1 byte
            offset = size_tal + size_stnum - 2

            excel_entry.append(goose[135 + offset])  # the first boolean
            excel_entry.append(goose[143 + offset])  # the second boolean
            if 0:
                byte_array = bytearray(goose)
                hexadecimal_string = byte_array.hex()
                print(hexadecimal_string)

        else:
            # Not a GOOSE frame
            excel_entry.append(0)


        # update the variables
        if packet_found == 1:
            # a packet has arrived
            lost_burst_size=0
        else:
            # the packet has NOT arrived
            if lost_burst_size == 0:
                # this is the first packet of a burst of lost packets
                # store the timestamp of the first lost packet of a burst
                timestamp_first_lost_packet=ts
            lost_burst_size += 1

        write_excel_row(sheet,current_packet,excel_entry)
        print('Added Excel row for packet #{}'.format(current_packet))
        last_ts = ts

        current_packet2 = 0


    print('')
    print('Saving Excel file...')
    workbook.close()
    print('Excel packet flow saved as: {}'.format(filename))

    print('*** Flow Information ***')
    print('* Total Packets: {} IP Packets: {} Non-IP Packets: {}'.format(packet_count1,ip_count,packet_count1-ip_count))
    print('* Capture Time: {:0.2f} seconds'.format(last_ts-first_ts))
    print('* Average Capture Data rate: {:0.2f} pps'.format(packet_count1/(last_ts-first_ts)))
    print('* VLAN Count: {}'.format(len(vlan_dict)))

if __name__ == "__main__":
    main()