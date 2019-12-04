from pythonping import ping
import pyaudio
import wave
import sys
import os

class AudioPlayer():
    chunk = 1024

    def __init__(self, file):
        """ Init audio stream """
        self.wf = wave.open(file, 'rb')
        self.p = pyaudio.PyAudio()
        self.stream = self.p.open(
            format = self.p.get_format_from_width(self.wf.getsampwidth()),
            channels = self.wf.getnchannels(),
            rate = self.wf.getframerate(),
            output = True
        )

    def play(self, start, end):
        """ Play entire file """
        frame_rate = self.wf.getframerate()

        start_frame = self.wf.setpos(int(frame_rate * start))

        data = self.wf.readframes(self.chunk)
        current_pos = self.wf.tell()
        while data != b'' and current_pos <= int(end * frame_rate):
            self.stream.write(data)
            data = self.wf.readframes(self.chunk)
            current_pos = self.wf.tell()

    def close(self):
        """ Graceful shutdown """
        self.stream.close()
        self.p.terminate()

if __name__ == "__main__":
    # Usage example for pyaudio
    a = AudioPlayer("sample_1202.wav")
    os.system("ping -c 1 1.1.1.1")
    a.play(start = 9, end = 11.5) # 0 - 11.5, 9 - 11.5.
    os.system("ping -c 1 8.8.4.4")
    #a.close()

