#%%
## SETUP

import nest_asyncio
nest_asyncio.apply()

import pyshark
import numpy as np
import matplotlib.pyplot as plt
import os

def get_time_secs(packet, start_time):
    time = packet.sniff_time-start_time
    time = time.seconds+time.microseconds/1e6
    return time

# set filename(s) to scan
script_dir = os.path.dirname(os.path.abspath(__file__))
base_dir = os.path.abspath(script_dir + '/../data')
filenames = ['output_ping_new_overnight.pcapng']
filenames = [base_dir + '/' + f for f in filenames]
filename = filenames[0]

# set filter for wireshark capture
disp_filter = 'ip and !dns'

# relevant ip addresses
echo_ip = '10.42.0.159'
pi_ip = '172.19.222.76'
server_ip = '52.119.197.96'
ping1_ip = '1.1.1.1'
ping2_ip = '8.8.4.4'
ping3_ip = '8.8.8.8'
ping4_ip = '9.9.9.9'

#%%
## BREAK DATA INTO TEST FRAMES
# Each test frame contains packet times and sizes, split by either
# source or destination address
cap = pyshark.FileCapture(filename, display_filter=disp_filter)
start_time = cap[0].sniff_time

out_times = [] # out_times[frame][dst_addr_index] gives list of packet times
out_sizes = [] # out_sizes[frame][dst_addr_index] gives list of packet sizes
out_dsts = [] # out_dsts[frame] gives list of destination addresses
in_times = [] # in lists follow same convention as out lists
in_sizes = []
in_srcs = []

in_frame = 0 # boolean indicating whether we are in a test frame or not
frame = 0 # current test frame number
for n,p in enumerate(cap):
    # start a test frame (on start of recording playback)
    if p.ip.src == pi_ip and p.ip.dst == ping1_ip:
        print('Start: {}, {}'.format(n, p.number))
        assert in_frame == 0
        in_frame = 1
        
        # add frame to list
        out_times.append([])
        out_sizes.append([])
        out_dsts.append([])
        # add ping destination to list (to make visualization easier)
        out_dsts[frame].append(p.ip.dst)
        out_times[frame].append([])
        out_sizes[frame].append([])
        # add ping packet to list
        i = len(out_dsts[frame]) - 1
        out_times[frame][i].append(get_time_secs(p, start_time))
        out_sizes[frame][i].append(1000)
        
        #add frame to list
        in_times.append([])
        in_sizes.append([])
        in_srcs.append([])
        # add ping destination to list (to make visualization easier)
        in_srcs[frame].append(p.ip.dst)
        in_times[frame].append([])
        in_sizes[frame].append([])
        # add ping packet to list
        i = len(in_srcs[frame]) - 1
        in_times[frame][i].append(get_time_secs(p, start_time))
        in_sizes[frame][i].append(1000)
    
    # end a test frame (on start of echo reply)
    if p.ip.src == pi_ip and p.ip.dst == ping3_ip:
        print('End: {}, {}'.format(n, p.number))
        assert in_frame == 1
        in_frame = 0

        # add ping destination to list (to make visualization easier)
        out_dsts[frame].append(p.ip.dst)
        out_times[frame].append([])
        out_sizes[frame].append([])
        # add ping packet to list
        i = len(out_dsts[frame]) - 1
        out_times[frame][i].append(get_time_secs(p, start_time))
        out_sizes[frame][i].append(1000)

        # add ping destination to list (to make visualization easier)
        in_srcs[frame].append(p.ip.dst)
        in_times[frame].append([])
        in_sizes[frame].append([])
        # add ping packet to list
        i = len(in_srcs[frame]) - 1
        in_times[frame][i].append(get_time_secs(p, start_time))
        in_sizes[frame][i].append(1000)

        frame = frame + 1

    # record data for test frame (on ssl packets)
    if in_frame and p.highest_layer == 'SSL' \
       and 'record_length' in p.ssl.field_names:
        # handle outgoing packets
        if p.ip.src == echo_ip:
            # get dst index if dst exists on list, otherwise add dst to list
            try:
                i = out_dsts[frame].index(p.ip.dst)
            except:
                out_dsts[frame].append(p.ip.dst)
                out_times[frame].append([])
                out_sizes[frame].append([])
                i = len(out_dsts[frame]) - 1
            # add packet to list
            out_times[frame][i].append(get_time_secs(p, start_time))
            out_sizes[frame][i].append(int(p.ssl.record_length))
        # handle incoming packets
        elif p.ip.dst == echo_ip:
            # get src index if src exists on list, otherwise add src to list
            try:
                i = in_srcs[frame].index(p.ip.src)
            except:
                in_srcs[frame].append(p.ip.src)
                in_times[frame].append([])
                in_sizes[frame].append([])
                i = len(in_srcs[frame]) - 1
            # add packet to list
            in_times[frame][i].append(get_time_secs(p, start_time))
            in_sizes[frame][i].append(int(p.ssl.record_length))
    # this is here to allow smaller chunk analysis for debugging
    # if n > 10000:
    #     break

#%%
## PLOT OUTGOING DATA BY FRAME
for frame in range(len(out_times)):
    times_plot = out_times[frame][:]
    sizes_plot = out_sizes[frame][:]
    dsts_plot = out_dsts[frame][:]
    # Drop destinations with fewer than 10 packets
    # delete_inds = []
    # for i,t in enumerate(times_plot):
    #     if len(t) < 10:
    #         delete_inds.append(i)
    # this construction is hacky, but it works (each time an item is deleted,
    #  the list size decreases, so indices need to change)
    # for i,ind in enumerate(delete_inds):
    #     del(times_plot[ind-i])
    #     del(sizes_plot[ind-i])
    #     del(dsts_plot[ind-i])

    # set bin size at 100 ms
    bins = np.arange(np.min(np.min(times_plot)),np.max(np.max(times_plot)), 0.1)

    plt.figure()
    # create histogram of packet counts
    # weird subplot stuff is for formatting reasons
    plt.subplot2grid((2,3),(0,0), colspan=2)
    plt.hist(times_plot, bins=bins, stacked=True)
    plt.title('Outbound Traffic')
    plt.ylabel('Number of Packets')
    plt.xlabel('Time (s)')

    # create histogram of packet sizes
    plt.subplot2grid((2,3),(1,0), colspan=2)
    plt.hist(times_plot, bins=bins, weights=sizes_plot, stacked=True)
    plt.ylabel('Amount of Data (bytes)')
    plt.xlabel('Time (s)')

    # create legend of destination addresses off to the side
    plt.subplot2grid((2,3),(0,2), rowspan=2)
    for x in out_times:
        plt.plot(0,0)
        plt.xticks([])
        plt.yticks([])
        plt.box('off')
    plt.legend(dsts_plot)
    plt.tight_layout()
    plt.show()


#%%
## PLOT INCOMING DATA BY FRAME
for frame in range(len(out_times)):
    times_plot = in_times[frame][:]
    sizes_plot = in_sizes[frame][:]
    srcs_plot = in_srcs[frame][:]
    # Drop sources with fewer than 10 packets
    # delete_inds = []
    # for i,t in enumerate(times_plot):
    #     if len(t) < 10:
    #         delete_inds.append(i)
    # this construction is hacky, but it works (each time an item is deleted,
    #  the list size decreases, so indices need to change)
    # for i,ind in enumerate(delete_inds):
    #     del(times_plot[ind-i])
    #     del(sizes_plot[ind-i])
    #     del(srcs_plot[ind-i])

    # set bin size at 100 ms
    bins = np.arange(np.min(np.min(times_plot)),np.max(np.max(times_plot)), 0.1)

    plt.figure()
    # create histogram of packet counts
    # weird subplot stuff is for formatting reasons
    plt.subplot2grid((2,3),(0,0), colspan=2)
    plt.hist(times_plot, bins=bins, stacked=True)
    plt.title('Inbound Traffic')
    plt.ylabel('Number of Packets')
    plt.xlabel('Time (s)')

    # create histogram of packet sizes
    plt.subplot2grid((2,3),(1,0), colspan=2)
    plt.hist(times_plot, bins=bins, weights=sizes_plot, stacked=True)
    plt.ylabel('Amount of Data (bytes)')
    plt.xlabel('Time (s)')

    # create legend of source addresses off to the side
    plt.subplot2grid((2,3),(0,2), rowspan=2)
    for x in times_plot:
        plt.plot(0,0)
        plt.xticks([])
        plt.yticks([])
        plt.box('off')
    plt.legend(srcs_plot)
    plt.tight_layout()
    plt.show()


# %%
## CALCULATE STATISTICS PER TEST FRAME
total_size_out = []
total_size_in = []

for x in out_sizes:
    total_size_out.append(np.sum(np.sum(x)))
for x in in_sizes:
    total_size_in.append(np.sum(np.sum(x)))

# plot total data size for all test frames
plt.figure()
plt.subplot(2,1,1)
plt.plot(total_size_out, '*')
plt.ylim(40000,75000)
plt.xlabel('Test number')
plt.ylabel('Outgoing data size')
plt.subplot(2,1,2)
plt.plot(total_size_in, '*')
plt.xlabel('Test number')
plt.ylabel('Incoming data size')
plt.tight_layout()
plt.show()

# %%