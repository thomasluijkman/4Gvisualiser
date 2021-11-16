import cv2.cv2 as cv2
import numpy as np
from PIL import Image


class Visualiser:
    font = cv2.FONT_HERSHEY_DUPLEX
    width = 800
    height = 640
    textscale = 0.4

    def __init__(self, data):
        self.data = data
        self.image = Image.new('RGB', (self.width, self.height), (255, 255, 255))
        self.packets_processed = 0

    def create_image(self, start=0):
        imga = np.array(self.image)
        imga = self.image_skeleton(imga)
        current_data = self.data[start:start+5]
        for packet in current_data:
            imga = self.process_packet(imga, packet)
        self.packets_processed = 0
        self.image = Image.fromarray(imga)
        self.image.show(title="This is an image")

    def process_packet(self, imga, packet):
        origin_height = 175 + (100 * self.packets_processed)
        self.packets_processed += 1
        pta = (100, origin_height)
        ptb = (700, origin_height)
        if packet.data.mac_lte.get('mac-lte.direction') == '1':
            tmp = pta
            pta = ptb
            ptb = tmp
        imga = cv2.arrowedLine(imga, pta, ptb, (0,0,0), thickness=5, tipLength=0.05)
        txtsize = cv2.getTextSize(packet.summary, self.font, self.textscale, 2)
        origin_width = 400 - txtsize[0][0]/2
        print(origin_width)
        imga = cv2.putText(imga, packet.summary, (int(origin_width), origin_height - 10), self.font, self.textscale, (0,0,0), thickness=1)
        return imga

    def image_skeleton(self, imga):
        imga = cv2.line(imga, (100, 100), (100, 600), (0, 0, 0), thickness=10)
        imga = cv2.line(imga, (700, 100), (700, 600), (0, 0, 0), thickness=10)
        imga = cv2.putText(imga, 'UE', (80, 90), self.font, 1, (0, 0, 0), thickness=2)
        imga = cv2.putText(imga, 'eNodeB', (640, 90), self.font, 1, (0, 0, 0), thickness=2)
        return imga
