"""Generate network.ico — a clean hub-and-spoke network symbol on a blue rounded
badge. Drawn large and downscaled (LANCZOS) for smooth anti-aliasing.
Run: python make_icon.py
"""
import math
from PIL import Image, ImageDraw

M = 1024
TOP = (77, 163, 255)   # gradient top  (#4DA3FF)
BOT = (28, 109, 208)   # gradient bottom(#1C6DD0)

# Vertical gradient background.
grad = Image.new("RGB", (M, M))
gd = ImageDraw.Draw(grad)
for y in range(M):
    t = y / (M - 1)
    gd.line([(0, y), (M, y)],
            fill=tuple(int(TOP[i] + (BOT[i] - TOP[i]) * t) for i in range(3)))

# Rounded-square mask.
mask = Image.new("L", (M, M), 0)
ImageDraw.Draw(mask).rounded_rectangle([0, 0, M - 1, M - 1], radius=int(M * 0.18), fill=255)

icon = Image.new("RGBA", (M, M), (0, 0, 0, 0))
icon.paste(grad, (0, 0), mask)
d = ImageDraw.Draw(icon)

cx, cy = M / 2, M / 2
R = M * 0.30
N = 6
nodes = [(cx + R * math.cos(math.radians(-90 + k * 360 / N)),
          cy + R * math.sin(math.radians(-90 + k * 360 / N))) for k in range(N)]

lw = int(M * 0.024)
WHITE = (255, 255, 255, 255)
# Spokes from the centre to each node.
for (x, y) in nodes:
    d.line([(cx, cy), (x, y)], fill=(255, 255, 255, 210), width=lw)
# Ring edges for a mesh look.
for k in range(N):
    x1, y1 = nodes[k]
    x2, y2 = nodes[(k + 1) % N]
    d.line([(x1, y1), (x2, y2)], fill=(255, 255, 255, 110), width=int(lw * 0.7))


def disc(x, y, r, fill):
    d.ellipse([x - r, y - r, x + r, y + r], fill=fill)


for (x, y) in nodes:
    disc(x, y, int(M * 0.062), WHITE)
disc(cx, cy, int(M * 0.090), WHITE)

sizes = [(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)]
master = icon.resize((256, 256), Image.LANCZOS)
master.save("network.ico", format="ICO", sizes=sizes)
print("wrote network.ico", sizes)
