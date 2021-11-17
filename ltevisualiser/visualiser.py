import tkinter as tk
from functools import partial

class Visualiser:
    def __init__(self, data):
        self.data = data
        self.window = tk.Tk()
        self.data_start = 0

    def visualise(self):
        self.create_image()
        self.window.title('LTE Packet Visualisation')
        self.window.mainloop()

    def create_image(self):
        canvas = tk.Canvas(width=950, height=670)
        canvas.pack(anchor=tk.CENTER)
        self.image_skeleton(canvas)
        current_data = self.data[self.data_start:self.data_start+5]
        i = 0
        for packet in current_data:
            origin_height = 175 + (100*i)
            self.process_packet(canvas, packet, origin_height)
            button = tk.Button(text='Show full packet', anchor=tk.NW, command=partial(self.show_packet, packet))
            canvas.create_window(800, origin_height-15, anchor=tk.NW, window=button)
            i += 1
        if self.data_start > 0:
            prev_button = tk.Button(text='Previous page', anchor=tk.NW, command=partial(self.update_image, canvas, -1))
            canvas.create_window(37, 620, anchor=tk.NW, window=prev_button)
        if self.data_start < len(self.data) - 5:
            next_button = tk.Button(text='Next page', anchor=tk.NW, command=partial(self.update_image, canvas, 1))
            canvas.create_window(650, 620, anchor=tk.NW, window=next_button)

    def update_image(self, canvas, direction=0):
        if direction == 0:
            canvas.pack_forget()
            self.create_image()
        elif direction == -1:
            self.data_start = max(0, self.data_start - 5)
            canvas.pack_forget()
            self.create_image()
        elif direction == 1:
            self.data_start = min(len(self.data) - 5, self.data_start + 5)
            canvas.pack_forget()
            self.create_image()

    def show_packet(self, packet):
        window = tk.Toplevel(self.window)
        horizontal_scroll = tk.Scrollbar(window, orient=tk.HORIZONTAL)
        horizontal_scroll.pack(side=tk.BOTTOM, fill=tk.X)
        vertical_scroll = tk.Scrollbar(window, orient=tk.VERTICAL)
        vertical_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        text = tk.Text(window, wrap=tk.NONE, xscrollcommand=horizontal_scroll.set, yscrollcommand=vertical_scroll.set)
        lines = str(packet.data).split('\n')
        for line in lines:
            text.insert(tk.END, line + '\n')
        text.pack(fill=tk.BOTH)
        horizontal_scroll.config(command=text.xview)
        vertical_scroll.config(command=text.yview)
        window.resizable(True, False)
        window.mainloop()

    def process_packet(self, canvas, packet, offset):
        xa = 100
        xb = 700
        if packet.data.mac_lte.get('mac-lte.direction') == '1':
            direction = tk.FIRST
        else:
            direction = tk.LAST
        canvas.create_line(xa, offset, xb, offset, arrow=direction, arrowshape=(20,30,10), width=4)
        canvas.create_text(400, offset - 20, fill='black', font='Courier 11', text=packet.summary)
        return canvas

    def image_skeleton(self, canvas):
        canvas.create_line(100, 100, 100, 600, width=10)
        canvas.create_line(700, 100, 700, 600, width=10)
        canvas.create_text(100, 80, fill='black', font='Arial 20', text='User Equipment')
        canvas.create_text(700, 80, fill='black', font='Arial 20', text='eNodeB')
        return canvas
