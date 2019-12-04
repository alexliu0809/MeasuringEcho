#%%
## SETUP

import nest_asyncio
nest_asyncio.apply()

import pyshark
import numpy as np
import matplotlib.pyplot as plt
import os

def print_summary_header():
    print('#\tTime\t\tSource\t\tDestination\tProtocol\tLength')

def print_summary(packet, start_time):
    time_sec = get_time_secs(packet, start_time)
    print('{num}\t{time:09.6f}\t{src}\t{dst}\t{layer}\t\t{length}'.format( \
           num=packet.number, src=packet.ip.src, dst=packet.ip.dst, \
           layer=packet.highest_layer, length=packet.length, time=time_sec))

def get_time_secs(packet, start_time):
    time = packet.sniff_time-start_time
    time = time.seconds+time.microseconds/1e6
    return time

script_dir = os.path.dirname(os.path.abspath(__file__))
base_dir = os.path.abspath(script_dir + '/../data')
# filenames = ['sample_1.pcapng', 'sample_2.pcapng', 'sample_1_1.pcapng', \
#              'sample_1_2.pcapng', 'sample_1_3.pcapng'] 
filenames = ['record_clear_overnight/sample_record_clear_overnight.pcapng']
filenames = [base_dir + '/' + f for f in filenames]
disp_filter = 'ip'
echo_ip = '10.42.0.159'
server_ip = '52.119.197.96'

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
    
    # ## TIME HISTOGRAM OUTGOING PACKETS BY DEST IP
    # cap_echo = [p for p in cap if p.ip.src == echo_ip and p.highest_layer == 'SSL']
    # times = []
    # sizes = []
    # dsts = []
    # for i,dst in enumerate(set([p.ip.dst for p in cap_echo])):
    #     times.append([])
    #     sizes.append([])
    #     gen = (p for p in cap_echo if p.ip.dst == dst)
    #     for p in gen:
    #         if 'record_length' in p.ssl.field_names:
    #             times[i].append(get_time_secs(p, start_time))
    #             sizes[i].append(int(p.ssl.record_length))
    #     dsts.append(dst)

    times = []
    sizes = []
    dsts = []
    for n,p in enumerate(cap):
        if p.ip.src == echo_ip \
           and p.highest_layer == 'SSL' \
           and 'record_length' in p.ssl.field_names:
            try:
                i = dsts.index(p.ip.dst)
            except:
                dsts.append(p.ip.dst)
                times.append([])
                sizes.append([])
                i = len(dsts) - 1
            times[i].append(get_time_secs(p, start_time))
            sizes[i].append(int(p.ssl.record_length))
        if n > 100000:
            break

#%%

    times_plot = times[:]
    sizes_plot = sizes[:]
    dsts_plot = dsts[:]
    delete_inds = []
    for i,t in enumerate(times_plot):
        if len(t) < 50:
            delete_inds.append(i)
    for i,ind in enumerate(delete_inds):
        del(times_plot[ind-i])
        del(sizes_plot[ind-i])
        del(dsts_plot[ind-i])
 
    for i in range(0,9):
        # bins = np.arange(0,np.max(np.max(times_plot)), 20)
        bins = np.arange(i*3000,(i+1)*3000, 20)

        plt.figure()
        plt.subplot2grid((2,3),(0,0), colspan=2)
        plt.hist(times_plot, bins=bins, stacked=True)
        plt.title('Outbound Traffic')
        plt.ylabel('Number of Packets')
        plt.xlabel('Time (s)')
        # plt.legend(dsts)

        plt.subplot2grid((2,3),(1,0), colspan=2)
        plt.hist(times_plot, bins=bins, weights=sizes_plot, stacked=True)
        plt.ylabel('Amount of Data (bytes)')
        plt.xlabel('Time (s)')
        # plt.legend(dsts)

        plt.subplot2grid((2,3),(0,2), rowspan=2)
        for x in times:
            plt.plot(0,0)
            plt.xticks([])
            plt.yticks([])
            plt.box('off')
        plt.legend(dsts_plot)
        plt.tight_layout()
        plt.show()


    # ## TIME HISTOGRAM INCOMING PACKETS BY SRC IP
    # cap_echo = [p for p in cap if p.ip.dst == echo_ip and p.highest_layer == 'SSL']
    # times = []
    # sizes = []
    # srcs = []
    # for i,src in enumerate(set([p.ip.src for p in cap_echo])):
    #     times.append([])
    #     sizes.append([])
    #     gen = (p for p in cap_echo if p.ip.src == src)
    #     for p in gen:
    #         if 'record_length' in p.ssl.field_names:
    #             times[i].append(get_time_secs(p, start_time))
    #             sizes[i].append(int(p.ssl.record_length))
    #     srcs.append(src)

    # bins = np.arange(0,np.max(np.max(times)))

    # plt.figure(filename)
    # plt.subplot(2,1,1)
    # plt.hist(times, bins=bins, stacked=True)
    # plt.ylabel('Number of Packets')
    # plt.xlabel('Time (s)')
    # plt.legend(srcs)

    # plt.subplot(2,1,2)
    # plt.hist(times, bins=bins, weights=sizes, stacked=True)
    # plt.ylabel('Amount of Data (bytes)')
    # plt.xlabel('Time (s)')
    # plt.legend(srcs)
    # plt.title('Inbound Traffic')
    # plt.show()

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

