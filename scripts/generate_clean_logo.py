from __future__ import annotations

from pathlib import Path
from typing import Iterable, Tuple

from PIL import Image, ImageDraw, ImageFilter, ImageFont


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "logo.png"
ICONS_DIR = ROOT / "apps/qypha-desktop/src-tauri/icons"

SIZE = 1024
BG = (7, 20, 43, 255)
BG_EDGE = (17, 53, 96, 255)
CYAN = (106, 245, 255, 255)
CYAN_SOFT = (41, 190, 230, 180)
WHITE = (244, 250, 255, 255)
MINT = (66, 245, 232, 220)
GHOST_FILL = (48, 235, 240, 178)


def font(size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    candidates = [
        "/System/Library/Fonts/Supplemental/Arial Rounded Bold.ttf",
        "/System/Library/Fonts/Supplemental/Avenir Next.ttc",
        "/System/Library/Fonts/SFNS.ttf",
        "/Library/Fonts/Arial.ttf",
    ]
    for candidate in candidates:
        if Path(candidate).exists():
            try:
                return ImageFont.truetype(candidate, size=size)
            except OSError:
                pass
    return ImageFont.load_default()


def glow(draw_target: Image.Image, base_fn, color: Tuple[int, int, int, int], radii: Iterable[int]) -> None:
    for radius in radii:
        overlay = Image.new("RGBA", draw_target.size, (0, 0, 0, 0))
        overlay_draw = ImageDraw.Draw(overlay)
        base_fn(overlay_draw, color)
        draw_target.alpha_composite(overlay.filter(ImageFilter.GaussianBlur(radius=radius)))


def draw_circuit_lines(draw: ImageDraw.ImageDraw) -> None:
    lines = [
        [(78, 244), (160, 326), (312, 326)],
        [(122, 612), (220, 612), (314, 708)],
        [(928, 455), (854, 455), (774, 455)],
        [(884, 236), (766, 236), (726, 284), (726, 372)],
        [(850, 805), (776, 731), (708, 731)],
        [(470, 82), (470, 250)],
        [(554, 66), (554, 246)],
        [(338, 94), (338, 242)],
        [(694, 92), (694, 228)],
        [(220, 820), (314, 726), (314, 642)],
        [(930, 572), (806, 572), (742, 572)],
        [(100, 780), (220, 780), (292, 708)],
        [(150, 430), (274, 430)],
    ]
    for line in lines:
        draw.line(line, fill=CYAN_SOFT, width=5)
        for x, y in line[:: max(1, len(line) - 1)]:
            draw.ellipse((x - 7, y - 7, x + 7, y + 7), fill=CYAN_SOFT)


def draw_shield(draw: ImageDraw.ImageDraw) -> None:
    shield = [
        (286, 304),
        (408, 224),
        (616, 224),
        (738, 304),
        (716, 598),
        (512, 762),
        (308, 598),
    ]
    draw.polygon(shield, fill=(239, 245, 255, 246))
    draw.line(shield + [shield[0]], fill=(174, 231, 255, 140), width=4)


def draw_ghost(draw: ImageDraw.ImageDraw) -> None:
    body = [
        (430, 214),
        (516, 198),
        (594, 222),
        (646, 292),
        (652, 386),
        (676, 458),
        (684, 546),
        (650, 626),
        (600, 640),
        (566, 704),
        (512, 678),
        (464, 724),
        (426, 666),
        (368, 688),
        (340, 616),
        (358, 552),
        (338, 468),
        (346, 370),
        (382, 290),
    ]
    draw.polygon(body, fill=GHOST_FILL, outline=(138, 255, 249, 235))
    draw.ellipse((450, 310, 490, 370), fill=(12, 54, 77, 210))
    draw.ellipse((536, 310, 576, 370), fill=(12, 54, 77, 210))
    draw.ellipse((468, 330, 478, 346), fill=(255, 255, 255, 140))
    draw.ellipse((554, 330, 564, 346), fill=(255, 255, 255, 140))


def draw_lock(draw: ImageDraw.ImageDraw) -> None:
    draw.rounded_rectangle((452, 432, 572, 560), radius=26, fill=WHITE)
    draw.rounded_rectangle((474, 368, 550, 470), radius=36, outline=WHITE, width=20)
    draw.ellipse((501, 472, 523, 494), fill=(19, 86, 138, 255))
    draw.rounded_rectangle((506, 492, 518, 530), radius=6, fill=(19, 86, 138, 255))


def draw_q_ring(draw_target: Image.Image) -> None:
    bbox = (118, 118, 822, 822)

    def ring(d: ImageDraw.ImageDraw, color: Tuple[int, int, int, int]) -> None:
        d.arc(bbox, start=16, end=348, fill=color, width=26)
        d.line([(668, 676), (784, 792)], fill=color, width=28)
        d.line([(742, 744), (820, 744)], fill=color, width=28)

    glow(draw_target, ring, (80, 236, 255, 170), [32, 18, 8])
    draw = ImageDraw.Draw(draw_target)
    ring(draw, CYAN)


def draw_inner_circuits(draw: ImageDraw.ImageDraw) -> None:
    center_lines = [
        [(512, 252), (512, 358)],
        [(448, 292), (448, 404)],
        [(576, 292), (576, 404)],
        [(370, 360), (446, 360)],
        [(578, 360), (656, 360)],
        [(408, 600), (454, 554)],
        [(618, 602), (570, 554)],
        [(512, 618), (512, 570)],
    ]
    for line in center_lines:
        draw.line(line, fill=(203, 252, 255, 135), width=4)
        for x, y in line:
            draw.ellipse((x - 5, y - 5, x + 5, y + 5), fill=(220, 252, 255, 120))


def draw_title(base: Image.Image) -> None:
    text = "Qypha"
    text_font = font(84)
    mask = Image.new("RGBA", base.size, (0, 0, 0, 0))
    mask_draw = ImageDraw.Draw(mask)
    bbox = mask_draw.textbbox((0, 0), text, font=text_font)
    w = bbox[2] - bbox[0]
    x = (SIZE - w) // 2
    y = 870
    for radius in (18, 8):
        glow_layer = Image.new("RGBA", base.size, (0, 0, 0, 0))
        glow_draw = ImageDraw.Draw(glow_layer)
        glow_draw.text((x, y), text, font=text_font, fill=(100, 228, 255, 190))
        base.alpha_composite(glow_layer.filter(ImageFilter.GaussianBlur(radius=radius)))
    final_draw = ImageDraw.Draw(base)
    final_draw.text((x, y), text, font=text_font, fill=WHITE)


def render_logo() -> Image.Image:
    base = Image.new("RGBA", (SIZE, SIZE), BG)
    border = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    border_draw = ImageDraw.Draw(border)
    border_draw.rounded_rectangle((4, 4, SIZE - 4, SIZE - 4), radius=98, outline=BG_EDGE, width=5)
    base.alpha_composite(border)

    circuits = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    draw_circuit_lines(ImageDraw.Draw(circuits))
    base.alpha_composite(circuits.filter(ImageFilter.GaussianBlur(radius=1.2)))
    base.alpha_composite(circuits)

    q_layer = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    draw_q_ring(q_layer)
    base.alpha_composite(q_layer)

    shield_layer = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    draw_shield(ImageDraw.Draw(shield_layer))
    base.alpha_composite(shield_layer)

    ghost_layer = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    glow(ghost_layer, lambda d, c: draw_ghost(d), (72, 240, 243, 100), [28, 14])
    draw_ghost(ImageDraw.Draw(ghost_layer))
    base.alpha_composite(ghost_layer)

    center_layer = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    draw_inner_circuits(ImageDraw.Draw(center_layer))
    draw_lock(ImageDraw.Draw(center_layer))
    base.alpha_composite(center_layer)

    draw_title(base)
    return base


def save_variants(image: Image.Image) -> None:
    image.save(OUTPUT)
    ICONS_DIR.mkdir(parents=True, exist_ok=True)
    for size, name in [
        (32, "32x32.png"),
        (128, "128x128.png"),
        (256, "128x128@2x.png"),
        (512, "icon.png"),
    ]:
        image.resize((size, size), Image.LANCZOS).save(ICONS_DIR / name)


def main() -> None:
    image = render_logo()
    save_variants(image)


if __name__ == "__main__":
    main()
