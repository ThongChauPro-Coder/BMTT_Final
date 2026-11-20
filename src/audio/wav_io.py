import wave

class WavHandler:
    
    @staticmethod
    def read_wav(file_path):
        with wave.open(file_path, 'rb') as wav_file:
            params = wav_file.getparams()
            frames = bytearray(wav_file.readframes(params.nframes))
        return params, frames
    
    @staticmethod
    def write_wav(output_path:str, params, sound_data:bytearray) -> None:
        with wave.open(output_path, 'wb') as wav_out:
            wav_out.setparams(params)
            wav_out.writeframes(sound_data)
            
    
    def __init__(self, file_path):
        self.file_path = file_path
        self.wav_file = None
        self.params = None
        self.frames = None

    def open(self):
        self.wav_file = wave.open(self.file_path, 'rb')
        self.params = self.wav_file.getparams()
        self.frames = bytearray(self.wav_file.readframes(self.params.nframes))
        self.wav_file.close()

    def save(self, output_path):
        with wave.open(output_path, 'wb') as wav_out:
            wav_out.setparams(self.params)
            wav_out.writeframes(self.frames)

