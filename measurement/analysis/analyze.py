#%%
## SETUP

import nest_asyncio
nest_asyncio.apply()

import pyshark
import numpy as np
import matplotlib.pyplot as plt

def print_summary_header():
    print('#\tTime\t\tSource\t\tDestination\tProtocol\tLength')

def print_summary(packet, start_time):
    time_sec = get_time_secs(packet, start_time)
    print('{num}\t{time:09.6f}\t{src}\t{dst}\t{layer}\t\t{length}'.format(num=packet.number, src=packet.ip.src, \
            dst=packet.ip.dst, layer=packet.highest_layer, length=packet.length, time=time_sec))

def get_time_secs(packet, start_time):
    time = packet.sniff_time-start_time
    time = time.seconds+time.microseconds/1e6
    return time


# filenames = ['sample_1.pcapng', 'sample_2.pcapng', 'sample_1_1.pcapng', \
            #  'sample_1_2.pcapng', 'sample_1_3.pcapng'] 
filenames = ['sample_1.pcapng']
disp_filter = '!arp'
echo_ip = '10.42.0.159'

# print_summary_header()
# for packet in cap:
#     if packet.ip.src == echo_ip:
#         print_summary(packet, start_time)

#%%
## TIME HISTOGRAM OUTGOING PACKETS
filename = filenames[0]
cap = pyshark.FileCapture(filename, display_filter=disp_filter)
start_time = cap[0].sniff_time

cap_echo = [p for p in cap if p.ip.src == echo_ip]
times = [get_time_secs(p, start_time) for p in cap_echo]
sizes = [int(p.length) for p in cap_echo]

bins = np.arange(0,np.max(times), 0.25)

plt.figure()
# plt.subplot(1,2,1)
plt.hist(times, bins=bins)
plt.ylabel('Number of Packets')
plt.xlabel('Time (s)')
plt.show()
# plt.subplot(1,2,2)
plt.figure()
plt.hist(times, weights=sizes, bins=bins)
plt.ylabel('Amount of Data (bytes)')
plt.xlabel('Time (s)')
plt.show()

#%%

for filename in filenames:
    cap = pyshark.FileCapture(filename, display_filter=disp_filter)
    start_time = cap[0].sniff_time
    
    ## TIME HISTOGRAM OUTGOING PACKETS BY DEST IP
    cap_echo = [p for p in cap if p.highest_layer == 'SSL']
    times = []
    sizes = []
    dsts = []
    for dst in set([p.ip.dst for p in cap_echo]):
        times.append([get_time_secs(p, start_time) for p in cap_echo if p.ip.dst == dst])
        sizes.append([int(p.ssl.record_length) for p in cap_echo if p.ip.dst == dst])
        dsts.append(dst)

    bins = np.arange(0,np.max(np.max(times)), 0.25)

    plt.figure(filename)
    plt.subplot(2,1,1)
    plt.hist(times, bins=bins, stacked=True)
    plt.ylabel('Number of Packets')
    plt.xlabel('Time (s)')
    plt.legend(dsts)

    plt.subplot(2,1,2)
    plt.hist(times, bins=bins, weights=sizes, stacked=True)
    plt.ylabel('Amount of Data (bytes)')
    plt.xlabel('Time (s)')
    plt.legend(dsts)
    plt.title('Outbound Traffic')
    plt.show()


    ## TIME HISTOGRAM INCOMING PACKETS BY SRC IP
    cap_echo = [p for p in cap if p.highest_layer == 'SSL']
    times = []
    sizes = []
    srcs = []
    for src in set([p.ip.src for p in cap_echo]):
        times.append([get_time_secs(p, start_time) for p in cap_echo if p.ip.src == src])
        sizes.append([int(p.ssl.record_length) for p in cap_echo if p.ip.src == src])
        srcs.append(src)

    bins = np.arange(0,np.max(np.max(times)), 0.25)

    plt.figure(filename)
    plt.subplot(2,1,1)
    plt.hist(times, bins=bins, stacked=True)
    plt.ylabel('Number of Packets')
    plt.xlabel('Time (s)')
    plt.legend(srcs)

    plt.subplot(2,1,2)
    plt.hist(times, bins=bins, weights=sizes, stacked=True)
    plt.ylabel('Amount of Data (bytes)')
    plt.xlabel('Time (s)')
    plt.legend(srcs)
    plt.title('Inbound Traffic')
    plt.show()

    # ## TIME HISTOGRAM OUTGOING PACKETS BY PROTOCOL
    # cap_echo = [p for p in cap if p.ip.src == echo_ip]
    # times = []
    # sizes = []
    # pcls = []
    # for pcl in set([p.highest_layer for p in cap_echo]):
    #     times.append([get_time_secs(p, start_time) for p in cap_echo if p.highest_layer == pcl])
    #     sizes.append([int(p.length) for p in cap_echo if p.highest_layer == pcl])
    #     pcls.append(pcl)

    # bins = np.arange(0,np.max(np.max(times)), 0.25)

    # plt.figure(filename)
    # plt.subplot(2,1,1)
    # plt.hist(times, bins=bins, stacked=True)
    # plt.ylabel('Number of Packets')
    # plt.xlabel('Time (s)')
    # plt.legend(pcls)

    # plt.subplot(2,1,2)
    # plt.hist(times, bins=bins, weights=sizes, stacked=True)
    # plt.ylabel('Amount of Data (bytes)')
    # plt.xlabel('Time (s)')
    # plt.legend(pcls)
    # plt.title('Outbound Traffic')
    # plt.show()

#%%

