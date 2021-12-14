import tkinter as tk
from functools import partial
from ELVis import list_categories

class Visualiser:
    def __init__(self, data):
        self.all_data = data
        self.data = data
        self.window = tk.Tk()
        self.data_start = 0
        self.selected = tk.StringVar(self.window)
        self.selected.set('All')
        self.categories = ['All']
        self.categories += list_categories(data)
        self.categories.sort()
        self.categories.remove('All')
        self.categories.insert(0, 'All')

    def visualise(self):
        """Creates the visualisation UI for the packet capture."""
        self.create_image()
        self.window.title('LTE Packet Visualisation')
        self.window.resizable = (False, False)
        self.window.mainloop()

    def create_image(self):
        """Creates the image for visualisation and all helper buttons."""
        canvas = tk.Canvas(width=950, height=670)
        canvas.pack(anchor=tk.CENTER)
        self.image_skeleton(canvas)
        current_data = self.data[self.data_start:self.data_start+5]
        i = 0

        # Adds packets and "show full packet" buttons
        for packet in current_data:
            origin_height = 175 + (100*i)
            self.process_packet(canvas, packet, origin_height)
            button = tk.Button(text='Show full packet', anchor=tk.NW, command=partial(self.show_packet, packet))
            canvas.create_window(800, origin_height-15, anchor=tk.NW, window=button)
            i += 1

        # Adds buttons which traverse the pages of packets
        if self.data_start > 0:
            prev_button = tk.Button(text='Previous page', anchor=tk.NW, command=partial(self.update_image, -1))
            canvas.create_window(37, 620, anchor=tk.NW, window=prev_button)
        if self.data_start < len(self.data) - 5:
            next_button = tk.Button(text='Next page', anchor=tk.NW, command=partial(self.update_image, 1))
            canvas.create_window(650, 620, anchor=tk.NW, window=next_button)

        # Adds selection menu of different parts of protocols
        filter_text = tk.Label(text='Select filter:', font='Arial 11')
        filter_text.pack(side=tk.LEFT)
        option_menu = tk.OptionMenu(self.window, self.selected, *self.categories)
        option_menu.pack(side=tk.LEFT)
        selection_button = tk.Button(self.window, text='Apply filter', command=self.filter_data)
        selection_button.pack(side=tk.LEFT)

        # Adds button which brings up a reference for different elements of the UI
        legend_button = tk.Button(self.window, text='Legend', command=self.legend)
        legend_button.pack(side=tk.RIGHT)

    def filter_data(self):
        """Filters data based on selected filter."""
        if self.selected.get() == 'All':
            self.data = self.all_data
        else:
            self.data = []
            protocol = self.selected.get()
            for packet in self.all_data:
                if protocol in packet.category:
                    self.data.append(packet)
        self.data_start = 0
        self.update_image()

    def update_image(self, direction=0):
        """Updates the image when different packets need to be shown."""
        for widget in self.window.winfo_children():
            widget.destroy()
        if direction == -1:
            self.data_start = max(0, self.data_start - 5)
        elif direction == 1:
            self.data_start = min(len(self.data) - 5, self.data_start + 5)
        self.create_image()

    def show_packet(self, packet):
        """Creates a new window which shows the full packet."""
        # TODO: ADD ANALYSIS RESULTS OF PACKET

        # create window and add scrollbars
        window = tk.Toplevel(self.window)
        horizontal_scroll = tk.Scrollbar(window, orient=tk.HORIZONTAL)
        horizontal_scroll.pack(side=tk.BOTTOM, fill=tk.X)
        vertical_scroll = tk.Scrollbar(window, orient=tk.VERTICAL)
        vertical_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # create text to be shown
        text = tk.Text(window, wrap=tk.NONE, xscrollcommand=horizontal_scroll.set, yscrollcommand=vertical_scroll.set)
        analysis = ''.join(packet.analysis) if not packet.analysis == [] else 'Packet has no warnings or errors.'
        lines = f"""-------------SHORT DESCRIPTION--------------
Summary: {packet.full_summary}
Categories: {packet.category}
Error score: {packet.eval}
------------------ANALYSIS------------------
{analysis.rstrip()}
--------------FULL PACKET DATA--------------
{packet.data}""".split('\n')
        for line in lines:
            text.insert(tk.END, line + '\n')
        text.pack(fill=tk.BOTH)

        # configure scroll bars and show window
        horizontal_scroll.config(command=text.xview)
        vertical_scroll.config(command=text.yview)
        window.title(f'Packet: {packet.summary}')
        window.resizable(True, False)
        window.mainloop()

    def process_packet(self, canvas, packet, offset):
        """Adds an arrow to the canvas and the summary line of the particular packet."""
        xa = 100
        xb = 700
        if packet.data.mac_lte.get('mac-lte.direction') == '1':
            direction = tk.FIRST
        else:
            direction = tk.LAST
        canvas.create_line(xa, offset, xb, offset, fill=packet.get_colour(), arrow=direction, arrowshape=(20,30,10), width=4)
        canvas.create_text(400, offset - 20, fill='black', font='Courier 11', text=packet.summary)
        return canvas

    def legend(self):
        """Creates window offering additional explanation about UI concepts."""
        window = tk.Toplevel(self.window)
        horizontal_scroll = tk.Scrollbar(window, orient=tk.HORIZONTAL)
        horizontal_scroll.pack(side=tk.BOTTOM, fill=tk.X)
        vertical_scroll = tk.Scrollbar(window, orient=tk.VERTICAL)
        vertical_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        text = """Explanation of the different symbols and colours used in ELVis:
        
        * Black arrow indicates the packet is not analysed and not part of any category.
        * Blue arrow indicates the packet is not analysed, yet is part of a category.
        * Arrows from left to right are packets travelling from the mobile device to 
          a mobile network base station.
        * Arrows from right to left are packets travelling from a mobile network base
          station to the mobile device.
        """
        text_label = tk.Text(window, wrap=tk.NONE, xscrollcommand=horizontal_scroll.set,
                             yscrollcommand=vertical_scroll.set)
        for line in text.split('\n'):
            text_label.insert(tk.END, line.lstrip() + '\n')
        text_label.pack(fill=tk.BOTH)
        horizontal_scroll.config(command=text_label.xview)
        vertical_scroll.config(command=text_label.yview)
        window.mainloop()

    def image_skeleton(self, canvas):
        """Creates the basis of the network diagram between the UE and eNodeB devices."""
        canvas.create_line(100, 100, 100, 600, width=10)
        canvas.create_line(700, 100, 700, 600, width=10)
        canvas.create_text(100, 80, fill='black', font='Arial 20', text='User Equipment')
        canvas.create_text(700, 80, fill='black', font='Arial 20', text='eNodeB')
        return canvas
