# Generates HashCalc.ico: the Arabic letter H (heh, initial form "هـ") on a blue tile.
# Usage: python tools/make_icon.py res/HashCalc.ico   (needs Pillow with Raqm; Windows fonts)
import sys
from PIL import Image, ImageDraw, ImageFont

GLYPH = "\u0647\u0640"                     # heh + tatweel = initial-form heh
FONT = "C:/Windows/Fonts/segoeuib.ttf"     # Segoe UI Bold (has Arabic)
SIZES = [16, 20, 24, 32, 40, 48, 64, 256]

def draw(size):
    s = size * 8                           # supersample for smooth edges
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([s*0.03, s*0.03, s*0.97, s*0.97], radius=s*0.2, fill=(32, 96, 200, 255))
    font = ImageFont.truetype(FONT, int(s*0.8), layout_engine=ImageFont.Layout.RAQM)
    l, t, r, b = d.textbbox((0, 0), GLYPH, font=font, direction="rtl")
    k = (s*0.70) / max(r-l, b-t)
    font = ImageFont.truetype(FONT, int(s*0.8*k), layout_engine=ImageFont.Layout.RAQM)
    l, t, r, b = d.textbbox((0, 0), GLYPH, font=font, direction="rtl")
    d.text(((s-(r-l))/2 - l, (s-(b-t))/2 - t), GLYPH, font=font, fill="white", direction="rtl")
    return img.resize((size, size), Image.LANCZOS)

imgs = {n: draw(n) for n in SIZES}
imgs[256].save(sys.argv[1], sizes=[(n, n) for n in SIZES], append_images=[imgs[n] for n in SIZES[:-1]])
