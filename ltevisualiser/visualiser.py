import cv2.cv2 as cv2
import numpy as np
import tkinter as tk
from PIL import Image


class Visualiser:
    font = cv2.FONT_HERSHEY_DUPLEX
    width = 800
    height = 640
    textscale = 0.4

    def __init__(self, data):
        self.data = data
        self.window = tk.Tk()
        self.packets_processed = 0

    def create_image(self, start=0):
        canvas = tk.Canvas(width=800, height=640)
        canvas.pack()
        self.image_skeleton(canvas)
        current_data = self.data[start:start+5]
        for packet in current_data:
            self.process_packet(canvas, packet)
        self.window.mainloop()

    def process_packet(self, canvas, packet):
        origin_height = 175 + (100 * self.packets_processed)
        self.packets_processed += 1
        xa = 100
        xb = 700
        ya = origin_height
        yb = origin_height
        if packet.data.mac_lte.get('mac-lte.direction') == '1':
            dir = tk.FIRST
        else:
            dir = tk.LAST
        canvas.create_line(xa, ya, xb, yb, arrow=dir, width=4)
        canvas.create_text(400, origin_height - 20, fill='black', font='Arial 11', text=packet.summary)
        return canvas

    def image_skeleton(self, canvas):
        canvas.create_line(100, 100, 100, 600, width=10)
        canvas.create_line(700, 100, 700, 600, width=10)
        canvas.create_text(100, 80, fill='black', font='Arial 20', text='User Equipment')
        canvas.create_text(700, 80, fill='black', font='Arial 20', text='eNodeB')
        return canvas
