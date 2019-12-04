from audio_player import AudioPlayer
from audio_recorder import AudioRecorder
import time
import os

if __name__ == "__main__":
    # Usage example for pyaudio
    while True:
        # play the audio
        a = AudioPlayer("sample_1202.wav")
        print("Start Playing: {}".format(time.time()))
        os.system("ping -c 1 1.1.1.1") # punch play start
        a.play(start = 0, end = 11.5)
        print("End Playing: {}".format(time.time()))
        os.system("ping -c 1 8.8.4.4") # punch play end
        a.close()

        # Start recording
        b = AudioRecorder()
        print("Waiting")
        print()
        time.sleep(180)


