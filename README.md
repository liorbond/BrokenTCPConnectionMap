# BrokenTCPConnectionMap

About:
    Mapping all broken TCP hand-shakes from given pcap

Requirments:
    Working with ubuntu 16.04 so all the dependencies taken from it's repo

Pre-installation:
    Should run 'pre_installation' bash script

Running:
    Should run 'build' bash script

Technical Decisions:
1. Should follow every SYN by its [Source IP, Source Port, Dest IP, Dest Port] or [TCP Stream] lets call it the 'key'
2. Should support retransmission - Should check the time between SYN packets sent by each key and ignore if time is lower then some threshlold
3. Should save for each key (without source port) the amount of failed connections
