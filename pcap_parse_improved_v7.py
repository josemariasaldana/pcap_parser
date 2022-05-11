#!/usr/bin/python3
# 
# adapted by Jose Saldana, Apr 2022, from an original
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
# ~/pcap_parser$ ./pcap_parse_improved_v3.py ../tm-eth0.pcap ../tm-eth0-3missing.pcap tm-eth0
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
import datetime
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
    write_excel_row(sheet,0,['PKT NUMBER','TIMESTAMP','TIME','VLAN','ETH SIZE','Arrived','acum burst size', 'added delay', 'burst size', 'GOOSE_time_allowed_to_live', 'GOOSE_stNum', 'bool1', 'bool2'])

    debug = 0 #debug level
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
                if (debug >= 1):
                    print('Packet #{} from trace 1 found in position #{} of trace 2'.format(current_packet, current_packet2))
                break

        if packet_found == 0:
            #lost_burst_size += 1
            lost_packets += 1
            if (debug >= 1):
                print('Packet #{} of trace 1 not found in trace 2'.format(current_packet))

        # store the missing packet in an Excel file

        # check the type. If it is IP, then increase the IP counter
        # not needed so far, but I keep it here just in case
        if eth.type==dpkt.ethernet.ETH_TYPE_IP:
            ip_count += 1
        if first_ts == -1:
            first_ts = ts

        # variable that will store a row for the Excel file
        excel_entry = []

        # add Excel column #1 with the number of the packet in trace 1
        excel_entry.append(current_packet)

        # add Excel column #2 with the timestamp
        excel_entry.append(ts-first_ts)

        # add Excel column with the absolute time. see https://stackoverflow.com/questions/44533950/python-timestamps-of-packets-using-dpkt
        excel_entry.append(str(datetime.datetime.utcfromtimestamp(ts)))

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

            position_at_goose = 1

            # move 11 positions. Point at the beginning of gocbRef
            position_at_goose += 10


            ## field 'godbRef'
            # there MUST be an '80' here
            assert (goose[position_at_goose]  == int('0x80', base=16))

            # move 1 position. Point at the size of gocbRef
            position_at_goose += 1

            # read the size of the gocbRef field
            size_gocbRef = goose[position_at_goose]

            if (debug >= 2):
                print('size_gocbRef is at position {}'.format(position_at_goose))
                print('size_gocbRef: {}'.format(size_gocbRef))

            # move to the next field
            position_at_goose += size_gocbRef + 1


            ## field 'Time allowed to Live'
            # there MUST be an '81' here
            assert (goose[position_at_goose]  == int('0x81', base=16))

            # move to the size
            position_at_goose += 1

            # read the size            
            size_tal = goose[position_at_goose]
            if (debug >= 2):
                print('size_tal is at position {}'.format(position_at_goose))
                print('size_tal: {}'.format(size_tal))

            # move to the value
            position_at_goose += 1

            # read the field
            if size_tal == 1:
                # size 1
                time_allowed = goose[position_at_goose]
            else:
                if size_tal == 2:
                    # the value is in two bytes
                    time_allowed = goose[position_at_goose]*256 + goose[position_at_goose + 1]
                else:
                    print ('bad value of size_tal{}: '.format(size_tal))
                    continue

            # add the value to the column
            excel_entry.append(time_allowed)
            if (debug >= 2):
                print('time_allowed to live: {}'.format(time_allowed))

            # move to the next field
            position_at_goose += size_tal


            ## field 'dataSet'
            # there MUST be an '82' here
            assert (goose[position_at_goose]  == int('0x82', base=16))

            # move to the size
            position_at_goose += 1

            # read the size of the field
            size_dataset = goose[position_at_goose]

            # move to the next field
            position_at_goose += size_dataset + 1


            ## field 'goID'
            # there MUST be an '83' here
            assert (goose[position_at_goose]  == int('0x83', base=16))

            # move to the size
            position_at_goose += 1

            # read the size of the field
            size_goID = goose[position_at_goose]

            # move to the next field
            position_at_goose += size_goID + 1


            ## field 't'
            # there MUST be an '84' here
            assert (goose[position_at_goose]  == int('0x84', base=16))

            # move to the size
            position_at_goose += 1

            # read the size of the field
            size_t = goose[position_at_goose]

            # move to the next field
            position_at_goose += size_t + 1


            ## field 'stNum'
            # there must be an '85' here
            assert (goose[position_at_goose]  == int('0x85', base=16))

            # move to the size
            position_at_goose += 1

            # read the size
            size_stnum = goose[position_at_goose]
            if (debug >= 2):
                print('size_stnum: {}'.format(size_stnum))

            # move to the value
            position_at_goose += 1

            # read the field
            if size_stnum == 1:
                stnum = goose[position_at_goose]
            else:
                if size_stnum == 2:
                    stnum = goose[position_at_goose]*256 + goose[position_at_goose + 1]
                else:
                    print('error in size_stnum: {}'.format(size_stnum))
                    continue

            # add the value to the column
            excel_entry.append(stnum)
            if (debug >= 2):
                print('stnum: {}'.format(stnum))

            # move to the next field
            position_at_goose += size_stnum


            ## field 'sqNum'
            # there MUST be an '86' here
            assert (goose[position_at_goose]  == int('0x86', base=16))

            # move to the size
            position_at_goose += 1

            # read the size of the field
            size_sqNum = goose[position_at_goose]

            # move to the next field
            position_at_goose += size_sqNum + 1


            ## field 'simulation'
            # there MUST be an '87' here
            assert (goose[position_at_goose]  == int('0x87', base=16))

            # move to the size
            position_at_goose += 1

            # read the size of the field
            size_simulation = goose[position_at_goose]

            # move to the next field
            position_at_goose += size_simulation + 1


            ## field 'confRev'
            # there MUST be an '88' here
            assert (goose[position_at_goose]  == int('0x88', base=16))

            # move to the size
            position_at_goose += 1

            # read the size of the field
            size_confRev = goose[position_at_goose]

            # move to the next field
            position_at_goose += size_confRev + 1


            ## field 'ndsCom'
            # there MUST be an '89' here
            assert (goose[position_at_goose]  == int('0x89', base=16))

            # move to the size
            position_at_goose += 1

            # read the size of the field
            size_ndsCom = goose[position_at_goose]

            # move to the next field
            position_at_goose += size_ndsCom + 1


            ## field 'numDatSetEntries'
            # there MUST be an '8a' here
            assert (goose[position_at_goose]  == int('0x8a', base=16))

            # move to the size
            position_at_goose += 1

            # read the size of the field
            size_numDatSetEntries = goose[position_at_goose]

            # move to the next field
            position_at_goose += size_numDatSetEntries + 1


            ## field 'allData'
            # there MUST be an 'ab' here
            assert (goose[position_at_goose]  == int('0xab', base=16))

            # move to the size
            position_at_goose += 1

            # read the size of the field
            size_addData = goose[position_at_goose]

            # move to the first data
            position_at_goose += 1


            ## read the first data
            # in our case, it MUST be a boolean, so there MUST be an '83' here
            assert (goose[position_at_goose]  == int('0x83', base=16))

            # move to the size
            position_at_goose += 1

            # read the size of the field
            size_firstBoolean = goose[position_at_goose]

            # it MUST be 1
            assert (goose[position_at_goose]  == 1)

            # read the value and add it to the Excel
            #it is in the next byte
            excel_entry.append(goose[position_at_goose + 1])

            # move to the second data
            position_at_goose += size_firstBoolean + 1


            ## read the second data
            # in our case, it MUST be a bit-string, so there MUST be an '84' here
            assert (goose[position_at_goose]  == int('0x84', base=16))

            # move to the size
            position_at_goose += 1

            # read the size of the data
            size_secondData = goose[position_at_goose]

            # move to the next data
            position_at_goose += size_secondData + 1


            ## read the third data
            # in our case, it MUST be a boolean, so there MUST be an '83' here
            assert (goose[position_at_goose]  == int('0x83', base=16))

            # move to the size
            position_at_goose += 1

            # read the size of the field
            size_secondBoolean = goose[position_at_goose]

            # it MUST be 1
            assert (goose[position_at_goose]  == 1)

            # read the value and add it to the Excel
            #it is in the next byte
            excel_entry.append(goose[position_at_goose + 1])

            # move to the third data
            position_at_goose += size_secondBoolean + 1

            if (debug >= 3):
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
        if (debug >= 1):
            print('Added Excel row for packet #{}'.format(current_packet))
        last_ts = ts

        current_packet2 = 0


    print('')
    print('Saving Excel file...')
    workbook.close()
    print('Excel packet flow saved as: {}'.format(filename))

    print('*** Flow Information ***')
    print('* Total Packets: {}. IP Packets: {}. Non-IP Packets: {}'.format(packet_count1,ip_count,packet_count1-ip_count))
    print('* Capture Time: {:0.2f} seconds'.format(last_ts-first_ts))
    print('* Average Capture Data rate: {:0.2f} pps'.format(packet_count1/(last_ts-first_ts)))
    print('* VLAN Count: {}'.format(len(vlan_dict)))

if __name__ == "__main__":
    main()