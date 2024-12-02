# config.py

class Config:
    def __init__(self, config_file='config.txt'):
        self.rules = []
        self.alert_channels = []
        self.interface = 'eth0'
        self.bpf_filter = 'tcp'
        self.load_config(config_file)

    def load_config(self, config_file):
        # Configuration loading logic remains the same
        pass  # Assuming the same as before
