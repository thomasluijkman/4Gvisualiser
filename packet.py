import pyshark

class Packet:
    def __init__(self, data, summary, analysis):
        self.data = data
        self.summary = summary
        self.eval = analysis

    def get_data(self):
        return self.data

    def get_eval(self):
        return self.eval

