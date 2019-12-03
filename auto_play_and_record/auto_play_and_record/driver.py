from audio_player import AudioPlayer
from audio_recorder import AudioRecorder
import time
from pythonping import ping

if __name__ == "__main__":
    # Usage example for pyaudio
    while True:
        a = AudioPlayer("sample.wav")
        ping("1.1.1.1",count=1)
        a.play()
        ping("8.8.8.8",count=1)
        a.close()
        print("start recording")
        b = AudioRecorder()
        print("Waiting")
        print()
        time.sleep(180)


