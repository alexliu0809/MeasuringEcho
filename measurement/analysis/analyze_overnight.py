#%%
## SETUP

import nest_asyncio
nest_asyncio.apply()

import pyshark
import numpy as np
import matplotlib.pyplot as plt
import os
from scipy import stats

def get_time_secs(packet, start_time):
    time = packet.sniff_time-start_time
    time = time.seconds+time.microseconds/1e6
    return time

# set file number to analyze (see filenames below)
file_test_number = 5

# set filename(s) to scan
script_dir = os.path.dirname(os.path.abspath(__file__))
base_dir = os.path.abspath(script_dir + '/../data/maindata')
filenames = ['1202/output_ping_new_overnight.pcapng',
             '1204/output_whole_prefix_overnight.pcapng',
             '1205/overnight_whole_2alter_prefix.pcapng',
             '1206/output_whole_postfix_overnight.pcapng',
             '1207/output_whole_nonpause_postfix.pcapng',
             '1207night/output_whole_silence_gap_overnight.pcapng']
filenames = [base_dir + '/' + f for f in filenames]
filename = filenames[file_test_number]
# set save directory
savedirs = ['../../results/1202/',
            '../../results/1204/',
            '../../results/1205/',
            '../../results/1206/',
            '../../results/1207/',
            '../../results/1207night/']
savedirs = [base_dir + '/' + f for f in savedirs]
savedir = savedirs[file_test_number]

# other test specific params
init_skip_a = [0, 0, 0, 0, 3, 0]
num_tests_a = [1, 19, 2, 3, 4, 8]
prefix_times_a = [[0],
                  [8.5, 8, 7.5, 7, 6.5, 6, 5.5, 5, 4.5, 4, 3.5, 3, 2.5, 2, 1.5, 1, 0.5, 0, 9],
                  [9,0],
                  [0, 0.5, 1],
                  [0,1,2,3],
                  [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8]]
                  


init_skip = init_skip_a[file_test_number]
num_tests = num_tests_a[file_test_number]
prefix_times = prefix_times_a[file_test_number]


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
        if in_frame != 0:
            print("Frame end not encountered, starting new test frame")
            frame = frame + 1
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
        if in_frame != 1:
            print("Frame end encountered before start, skipping")
            continue
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

    # record ping2 spot
    if in_frame and p.ip.dst == ping2_ip and p.ip.src == pi_ip:
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
        out_sizes[frame][i].append(1000)

        # get src index if src exists on list, otherwise add src to list
        try:
            i = in_srcs[frame].index(p.ip.dst)
        except:
            in_srcs[frame].append(p.ip.dst)
            in_times[frame].append([])
            in_sizes[frame].append([])
            i = len(in_srcs[frame]) - 1
        # add packet to list
        in_times[frame][i].append(get_time_secs(p, start_time))
        in_sizes[frame][i].append(1000)
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

# get sum of data for each test frame
for x in out_sizes[init_skip:]:
    # total_size_out.append(np.sum(np.sum(x)))
    total_size_out.append(np.max([np.sum(y) for y in x]))
for x in in_sizes[init_skip:]:
    # total_size_in.append(np.sum(np.sum(x)))
    total_size_in.append(np.max([np.sum(y) for y in x]))

# do some filtering (z-value method)
# def filt(x, z):
#     if z < 3:
#         return x
#     else:
#         return np.nan

# z_out = np.abs(stats.zscore(total_size_out))
# total_size_out_filt = [filt(x,z) for z,x in zip(z_out, total_size_out)]
# z_in = np.abs(stats.zscore(total_size_in))
# total_size_in_filt = [filt(x,z) for z,x in zip(z_in, total_size_in)]

# do some filtering (IQR method)
def filt(x, q1, q3, iqr):
    if x > q1-1.5*iqr and x < q3+1.5*iqr:
        return x
    else:
        print('Filtered value {}'.format(x))
        return np.nan

q1_out = np.quantile(total_size_out, 0.25)
q3_out = np.quantile(total_size_out, 0.75)
iqr_out = q3_out-q1_out
total_size_out_filt = [filt(x, q1_out, q3_out, iqr_out) for x in total_size_out]

q1_in = np.quantile(total_size_in, 0.25)
q3_in = np.quantile(total_size_in, 0.75)
iqr_in = q3_in-q1_in
total_size_in_filt = [filt(x, q1_in, q3_in, iqr_in) for x in total_size_in]


# plot total data size for all test frames
plt.figure()
plt.subplot(2,1,1)
plt.plot(total_size_out_filt, '*')
# plt.ylim(40000,75000)
plt.xlabel('Test number')
plt.ylabel('Outgoing data size (bytes)')
plt.subplot(2,1,2)
plt.plot(total_size_in_filt, '*')
plt.xlabel('Test number')
plt.ylabel('Incoming data size (bytes)')
plt.tight_layout()
plt.show()

# # plot histograms
num_bins = 20
plt.figure()
plt.subplot(2,1,1)
plt.hist(total_size_out_filt, num_bins)
plt.xlabel('Outgoing data size (bytes)')
plt.ylabel('Frequency')
plt.subplot(2,1,2)
plt.hist(total_size_in_filt, num_bins)
plt.xlabel('Incoming data size (bytes)')
plt.ylabel('Frequency')
plt.tight_layout()
plt.show()

# %%
## STATISTICS BY PREFIX LENGTH

# calculate mean and std across each prefix length (stride across data)
means_out = []
stds_out = []
means_in = []
stds_in = []
for i in range(num_tests):
    means_out.append(np.nanmean(total_size_out_filt[i::num_tests]))
    stds_out.append(np.nanstd(total_size_out_filt[i::num_tests]))
    means_in.append(np.nanmean(total_size_in_filt[i::num_tests]))
    stds_in.append(np.nanstd(total_size_in_filt[i::num_tests]))

# plot average size with error bars against prefix length
plt.figure()
plt.errorbar(prefix_times, means_out, yerr=stds_out, fmt='*')
plt.xlabel('Postfix Time (s)')
plt.ylabel('Average Outgoing Data Size (bytes)')
plt.show()

plt.figure()
plt.errorbar(prefix_times, means_in, yerr=stds_in, fmt='*')
plt.xlabel('Postfix Time (s)')
plt.ylabel('Average Incoming Data Size (bytes)')
plt.show()



# %%
## STATISTICS BY PREFIX LENGTH SEPARATE PLOTS FOR RESPONSE/NO RESP

def sep(x, i, retResp):
    if ping3_ip in out_dsts[init_skip+i]:
        if retResp == True:
            return x
        else:
            return np.nan
    else:
        if retResp == True:
            return np.nan
        else:
            return x

# split into resp sizes and no resp sizes
resp_sizes_out = [sep(x,i,True) for i,x in enumerate(total_size_out_filt)]
noresp_sizes_out = [sep(x,i,False) for i,x in enumerate(total_size_out_filt)]
resp_sizes_in = [sep(x,i,True) for i,x in enumerate(total_size_in_filt)]
noresp_sizes_in = [sep(x,i,False) for i,x in enumerate(total_size_in_filt)]

# calculate mean and std across each prefix length (stride across data)
resp_means_out = []
resp_stds_out = []
resp_means_in = []
resp_stds_in = []
for i in range(num_tests):
    resp_means_out.append(np.nanmean(resp_sizes_out[i::num_tests]))
    resp_stds_out.append(np.nanstd(resp_sizes_out[i::num_tests]))
    resp_means_in.append(np.nanmean(resp_sizes_in[i::num_tests]))
    resp_stds_in.append(np.nanstd(resp_sizes_in[i::num_tests]))
noresp_means_out = []
noresp_stds_out = []
noresp_means_in = []
noresp_stds_in = []
for i in range(num_tests):
    noresp_means_out.append(np.nanmean(noresp_sizes_out[i::num_tests]))
    noresp_stds_out.append(np.nanstd(noresp_sizes_out[i::num_tests]))
    noresp_means_in.append(np.nanmean(noresp_sizes_in[i::num_tests]))
    noresp_stds_in.append(np.nanstd(noresp_sizes_in[i::num_tests]))

resp_counts = []
noresp_counts = []
for i in range(num_tests):
    resp_counts.append(np.sum([1 for x in resp_sizes_out[i::num_tests] if np.isfinite(x)]))
    noresp_counts.append(np.sum([1 for x in noresp_sizes_out[i::num_tests] if np.isfinite(x)]))
    

# plot average size with error bars against prefix length
plt.figure()
plt.errorbar(prefix_times, resp_means_out, yerr=resp_stds_out, fmt='*')
plt.errorbar(prefix_times, noresp_means_out, yerr=noresp_stds_out, fmt='*')
plt.legend(['Response', 'No response'])
plt.xlabel('Time Gap (s)')
plt.ylabel('Average Outgoing Data Size (bytes)')
plt.show()

plt.figure()
plt.errorbar(prefix_times, resp_means_in, yerr=resp_stds_in, fmt='*')
plt.errorbar(prefix_times, noresp_means_in, yerr=noresp_stds_in, fmt='*')
plt.legend(['Response', 'No response'])
plt.xlabel('Time Gap (s)')
plt.ylabel('Average Incoming Data Size (bytes)')
plt.show()

plt.figure()
plt.bar(prefix_times, resp_counts, width = 0.08)
plt.bar(prefix_times, noresp_counts, width = 0.08, bottom=resp_counts)
plt.legend(['Response', 'No response'])
plt.xlabel('Time Gap (s)')
plt.ylabel('Response Breakdown')
plt.ylim(top=16)
plt.show()

# %%
## STATISTICS BY PREFIX LENGTH SEPARATE PLOTS FOR INCOMING RESPONSE SIZE

def sep(x, i, level):
    bounds = [0, 10000, 20000, 30000]
    cmp_val = total_size_in_filt[i]
    if np.isnan(cmp_val):
        return np.nan
    elif cmp_val >= bounds[level] and cmp_val < bounds[level+1]:
        return x
    else:
        return np.nan

# split into sizes by response
split_sizes_out = []
split_sizes_in = []
for n in range(3):
    split_sizes_out.append([sep(x,i,n) for i,x in enumerate(total_size_out_filt)])
    split_sizes_in.append([sep(x,i,n) for i,x in enumerate(total_size_in_filt)])


# calculate mean and std across each prefix length (stride across data)
split_means_out = []
split_stds_out = []
split_means_in = []
split_stds_in = []
for j in range(3):
    split_means_out.append([])
    split_stds_out.append([])
    split_means_in.append([])
    split_stds_in.append([])
    for i in range(num_tests):
        split_means_out[j].append(np.nanmean(split_sizes_out[j][i::num_tests]))
        split_stds_out[j].append(np.nanstd(split_sizes_out[j][i::num_tests]))
        split_means_in[j].append(np.nanmean(split_sizes_in[j][i::num_tests]))
        split_stds_in[j].append(np.nanstd(split_sizes_in[j][i::num_tests]))


split_counts = []
for j in range(3):
    split_counts.append([])
    for i in range(num_tests):
        split_counts[j].append(np.sum([1 for x in split_sizes_out[j][i::num_tests] if np.isfinite(x)]))
    

# plot average size with error bars against prefix length
plt.figure()
for i in range(3):
    plt.errorbar(prefix_times, split_means_out[i], yerr=split_stds_out[i], fmt='*')
plt.legend(['No reply', 'Error reply', 'Correct reply'])
plt.xlabel('Time Gap (s)')
plt.ylabel('Average Outgoing Data Size (bytes)')
plt.show()

plt.figure()
for i in range(3):
    plt.errorbar(prefix_times, split_means_in[i], yerr=split_stds_in[i], fmt='*')
plt.legend(['No reply', 'Error reply', 'Correct reply'])
plt.xlabel('Time Gap (s)')
plt.ylabel('Average Incoming Data Size (bytes)')
plt.show()

plt.figure()
plt.bar(prefix_times, split_counts[0], width = 0.08)
plt.bar(prefix_times, split_counts[1], width = 0.08, bottom=split_counts[0])
plt.bar(prefix_times, split_counts[2], width = 0.08, bottom=[sum(x) for x in zip(split_counts[0], split_counts[1])])
plt.legend(['No reply', 'Error reply', 'Correct reply'], ncol=3)
plt.xlabel('Time Gap (s)')
plt.ylabel('Reply Type Breakdown')
plt.ylim(top=15)
plt.show()


# %%
## SAVE DATA TO FILE TO AVOID NEED FOR RE-ANALYZING
savefile = savedir + 'framedata.npy'
np.save(savefile, [out_dsts, out_times, out_sizes, in_srcs, in_times, in_sizes], allow_pickle=True)

# %%
## RESTORE DATA FROM FILE IF IT EXISTS
savefile = savedir + 'framedata.npy'
if (os.path.isfile(savefile)):
    tmp = np.load(savefile, allow_pickle=True)
    [out_dsts, out_times, out_sizes, in_srcs, in_times, in_sizes] = tmp.tolist()
else:
    print("File doesn't exist")


# %%
