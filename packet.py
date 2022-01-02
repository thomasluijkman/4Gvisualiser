from analyser.categoriser import categorise


class Packet:
    def __init__(self, *args):  # data = 0, summary = 1, raw = 2, analysis = 3
        if len(args) == 4:
            self.data = args[0].layers[2]  # for the purpose of this thesis, only care about RRC/MAC/NAS/RLC packets
            self.full_summary = args[1]
            self.summary, self.id = self.process_summary(args[1])
            self.eval = args[3]
            self.raw = bytes(args[2].get_raw_packet())
            self.category = categorise(self)
            self.analysis = []

    def __str__(self):
        return self.full_summary

    def process_summary(self, summary):
        """Processes summary to not be longer than 63 characters to fit in the graph."""
        split = summary.split(' ')
        id = int(split[0])
        words = split[2:]
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
        return sentence, id

    def add_analysis(self, sentence, severity=1, custom_preamble=None):
        self.eval += severity
        if custom_preamble:
            self.analysis.append(f'{custom_preamble}: {sentence}\n')
        elif severity == 0:
            self.analysis.append(f'Note: {sentence}\n')
        elif severity == 1:
            self.analysis.append(f'Warning: {sentence}\n')
        elif severity == 2:
            self.analysis.append(f'WARNING: {sentence}\n')
        elif severity == 3:
            self.analysis.append(f'Error: {sentence}\n')
        elif severity == 4:
            self.analysis.append(f'ERROR: {sentence}\n')


    def get_colour(self, max=0):
        """Assigns a color to the packet whenever it is required."""
        colour = (0, 0, 0)  # rgb
        if 'Unassigned' not in self.category:
            colour = (0, 0, 128)
        if 'Analysed' in self.category:
            if self.eval == 0 and len(self.analysis) == 0:  # packet has no warnings or errors
                colour = (0, 200, 0)
            elif self.eval == 0 and not len(self.analysis) == 0:  # packet only has notes but no warnings or errors
                colour = (0, 100, 0)
            elif max == 0:  # packet has errors, but no colour gradient will be applied
                colour = (255, 175, 0)
            else:  # packet has errors and colour gradient will be applied
                gradient = 1 - (self.eval / max) if self.eval > 1 else 1
                colour = (255, int(175 * gradient), 0)
        return '#%02x%02x%02x' % colour  # based on https://stackoverflow.com/questions/51591456/can-i-use-rgb-in-tkinter/51592104 (accessed 12/12/21)
