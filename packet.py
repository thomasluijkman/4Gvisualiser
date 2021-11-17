import pyshark

class Packet:
    def __init__(self, data, summary, analysis):
        self.data = data
        self.summary = self.process_summary(summary)
        self.eval = analysis

    def process_summary(self, summary):
        words = summary.split(' ')[2:]
        sentence = []
        for word in words:
            if not word:
                continue
            if (len(' '.join(sentence)) + len(word)) < 60:
                sentence.append(word)
            else:
                sentence.append('...')
                break
        sentence = ' '.join(sentence)
        return sentence

    def get_data(self):
        return self.data

    def get_eval(self):
        return self.eval

