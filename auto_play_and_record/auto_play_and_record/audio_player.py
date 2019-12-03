from pythonping import ping
import pyaudio
import wave
import sys

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

    def play(self):
        """ Play entire file """
        data = self.wf.readframes(self.chunk)
        while data != b'':
            self.stream.write(data)
            data = self.wf.readframes(self.chunk)

    def close(self):
        """ Graceful shutdown """
        self.stream.close()
        self.p.terminate()

if __name__ == "__main__":
    # Usage example for pyaudio
    a = AudioPlayer("sample.wav")
    #ping("1.1.1.1",count=1)
    a.play()
    #print("8.8.8.8",count=1)
    a.close()

