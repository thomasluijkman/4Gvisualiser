import cv2.cv2 as cv2
import numpy as np
from PIL import Image

class Visualiser:
    def __init__(self, data):
        self.data = data
        self.image = Image.new('RGB', (800, 640), (255, 255, 255))

    def create_image(self, start):
        self.draw_arrow((10, 20), (30, 30))

    def draw_arrow(self, point_a, point_b, width=1, color=(0, 0, 0)):
        image_array = np.array(self.image)
        image_array = cv2.arrowedLine(image_array, point_a, point_b, color, width)
        self.image = Image.fromarray(image_array)
        self.image.show()
