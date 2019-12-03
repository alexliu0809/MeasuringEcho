# Ref: https://github.com/jeysonmc/python-google-speech-scripts/blob/b1b3792cae9882ff678eed3017f63c60a4cd44f0/stt_google.py#L62
from sys import byteorder
from array import array
from struct import pack
import os
import pyaudio
import wave
import audioop
import math
from collections import deque
import time
import os

NOISE_THRESHOLD = 3000

CHUNK = 1024
FORMAT = pyaudio.paInt16
RATE = 23000
CHANNELS = 1

SILENCE_LIMIT = 1

PREV_AUDIO = 0.5  # Previous audio (in seconds) to prepend. When noise
                  # is detected, how much of previously recorded audio is
                  # prepended. This helps to prevent chopping the beggining
                  # of the phrase.

def listen_for_speech():
    """
    Listens to Microphone, extracts phrases from it and sends it to 
    Google's TTS service and returns response. a "phrase" is sound 
    surrounded by silence (according to threshold). num_phrases controls
    how many phrases to process before finishing the listening process 
    (-1 for infinite). 
    """

    #Open stream
    p = pyaudio.PyAudio()

    stream = p.open(format=FORMAT,
                    channels=CHANNELS,
                    rate=RATE,
                    input=True,
                    frames_per_buffer=CHUNK)

    print("* Listening mic. ")
    audio2send = []
    cur_data = ''  # current chunk  of audio data
    rel = RATE/CHUNK
    slid_win = deque(maxlen=int(SILENCE_LIMIT * rel))
    #Prepend audio from 0.5 seconds before noise was detected
    prev_audio = deque(maxlen=int(PREV_AUDIO * rel))
    started = False
    response = []

    while True:
        cur_data = stream.read(CHUNK)
        slid_win.append(math.sqrt(abs(audioop.avg(cur_data, 4))))
        #print slid_win[-1]
        if(sum([x > NOISE_THRESHOLD for x in slid_win]) > 0):
            if(not started):
                print("Starting record of phrase: {}".format(time.time()))
                os.system("ping -c 1 8.8.8.8")
                started = True
            audio2send.append(cur_data)
        elif (started is True):
            print("Done recording: {}".format(time.time()))
            os.system("ping -c 1 9.9.9.9")
            # The limit was reached, finish capture and deliver.
            filename = save_speech(list(prev_audio) + audio2send, p)
            break
        else:
            prev_audio.append(cur_data)

    stream.close()
    p.terminate()

    return response

def save_speech(data, p):
    """ Saves mic data to temporary WAV file. Returns filename of saved 
        file """

    filename = 'output_'+str(int(time.time()))
    # writes data to WAV file
    data = b''.join(data)
    wf = wave.open(filename + '.wav', 'wb')
    wf.setnchannels(1)
    wf.setsampwidth(p.get_sample_size(pyaudio.paInt16))
    wf.setframerate(16000)  # TODO make this value a function parameter?
    wf.writeframes(data)
    wf.close()
    return filename + '.wav'


class AudioRecorder():
    def __init__(self):
        listen_for_speech()


def audio_int(num_samples=50):
    """ Gets average audio intensity of your mic sound. You can use it to get
        average intensities while you're talking and/or silent. The average
        is the avg of the 20% largest intensities recorded.
    """

    print("Getting intensity values from mic.")
    p = pyaudio.PyAudio()

    stream = p.open(format=FORMAT,
                    channels=CHANNELS,
                    rate=RATE,
                    input=True,
                    frames_per_buffer=CHUNK)

    values = [math.sqrt(abs(audioop.avg(stream.read(CHUNK), 4))) 
              for x in range(num_samples)] 
    values = sorted(values, reverse=True)
    r = sum(values[:int(num_samples * 0.2)]) / int(num_samples * 0.2)
    print(" Finished ")
    print(" Average audio intensity is {}".format(r))
    stream.close()
    p.terminate()
    return r

if __name__ == '__main__':
    #a = AudioRecorder()
    audio_int()
