import pyshark

class Packet:
    def __init__(self, data, analysis):
        self.data = data
        self.eval = analysis

    def get_data(self):
        return self.data

    def get_eval(self):
        return self.eval

