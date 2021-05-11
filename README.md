# pcap_parse_improved_v3
Generates traffic summary statistucs & an excel file from a pcap

# Description:
Script that compares two .pcap files looking for lost packets. It creates an .xlsx file reporting the additional delay caused by packet loss.

# Important Notes:
Takes a long time for large pcap files ~30 seconds per GB on my mac + file save time - larger CPU will assist this.

# Usage:
```
usage example
~/pcap_parser$ ./pcap_parse_improved_v3.py ../tm-eth0.pcap ../tm-eth0-3missing.pcap tm-eth0.xlsx
where
- tm-eth0.pcap is the origin pcap file (no lost packets)
- tm-eth0-3missing.pcap is the pcap file at the destination (lost packets)
- th-eth0.xlsx is the output file where the results wil be reported. You will have the
  length of each burst, and the additional delay caused by each loss burst, measured
  as the difference between the original timestamp of the first received packet after the burst
  minus the original timestamp of the first lost packet of the burst
   1   t=1.0       Arrived
   2   t=3.0       Arrived
   3   t=6.0       Lost
   4   t=10.0      Lost
   5   t=11.0      Arrived

   this will be the result:
   nr  timestamp           lost?       acum burst  added delay burst size
   1   1.0         ...     Arrived     0           0           0
   2   3.0         ...     Arrived     0           0           0
   3   6.0         ...     Lost        1           0           0
   4   10.0        ...     Lost        2           0           0
   5   11.0        ...     Arrived     0           5.0         2       <-  the two last columns are only added after a burst
                                                                           5.0 = 11.0 - 6.0 
```
