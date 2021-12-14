from analyser.categoriser import categorise


class Packet:
    def __init__(self, *args):  # data = 0, summary = 1, analysis = 2
        if len(args) == 3:
            self.data = args[0]
            self.full_summary = args[1]
            self.summary = self.process_summary(args[1])
            self.eval = args[2]
            self.category = categorise(args[0], args[1])
            self.analysis = []

    def process_summary(self, summary):
        """Processes summary to not be longer than 63 characters to fit in the graph."""
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
        # TODO: GIVE PACKET DIFFERENT COLOR BASED ON ANALYSIS RESULTS
        colour = (0, 0, 0)  # rgb
        if 'Unassigned' not in self.category:
            colour = (0, 0, 128)
        if 'Analysed' in self.category:
            if self.eval == 0:  # packet has no warnings or errors
                colour = (0, 100, 0)
            elif max == 0:  # packet has errors, but no colour gradient will be applied
                colour = (255, 175, 0)
        return '#%02x%02x%02x' % colour  # based on https://stackoverflow.com/questions/51591456/can-i-use-rgb-in-tkinter/51592104 (accessed 12/12/21)
