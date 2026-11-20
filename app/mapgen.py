"""Offline map renderer.

No external tile server, no MapGlot, no network call. The basemap is a
schematic equirectangular world (coarse continent outlines + graticule); the
markers are the GeoLite2 coordinates of the mail's origin servers. This is a
location *aid*, not a street map, and the report says so explicitly.
"""
import io
import math

from PIL import Image, ImageDraw, ImageFont

W, H = 1200, 600
SEA = (232, 242, 248)
LAND = (206, 224, 205)
COAST = (96, 128, 104)
GRID = (190, 205, 214)
TEXT = (30, 45, 55)
MARK = (190, 30, 45)

# Very coarse continent outlines (lon, lat). Enough for a schematic overview.
CONTINENTS = [
    [(-168, 65), (-140, 70), (-120, 72), (-95, 74), (-75, 70), (-60, 60),
     (-55, 50), (-65, 45), (-70, 42), (-75, 35), (-81, 25), (-97, 26),
     (-105, 20), (-115, 30), (-125, 40), (-135, 55), (-150, 60), (-168, 65)],
    [(-81, 12), (-70, 12), (-60, 8), (-50, 0), (-35, -5), (-38, -20),
     (-48, -30), (-58, -40), (-65, -55), (-72, -52), (-75, -40),
     (-80, -20), (-81, 12)],
    [(-10, 36), (0, 44), (10, 45), (20, 40), (30, 45), (40, 48),
     (30, 60), (20, 70), (5, 70), (-5, 60), (-10, 50), (-10, 36)],
    [(-17, 15), (0, 35), (15, 37), (32, 31), (43, 12), (51, 12),
     (40, -5), (35, -25), (20, -35), (10, -30), (0, -5), (-17, 15)],
    [(30, 45), (60, 45), (90, 50), (120, 50), (140, 45), (160, 60),
     (180, 65), (180, 10), (140, 0), (120, -10), (100, 0), (80, 8),
     (60, 25), (45, 30), (30, 45)],
    [(113, -22), (130, -12), (145, -15), (153, -28), (145, -38),
     (130, -32), (113, -22)],
    [(-45, 60), (-20, 70), (-20, 82), (-60, 82), (-60, 70), (-45, 60)],
    [(-180, -70), (180, -70), (180, -85), (-180, -85)],
]


def _xy(lon, lat, w=W, h=H):
    return ((float(lon) + 180.0) / 360.0 * w,
            (90.0 - float(lat)) / 180.0 * h)


def _font(size):
    for name in ("arial.ttf", "segoeui.ttf", "DejaVuSans.ttf"):
        try:
            return ImageFont.truetype(name, size)
        except Exception:
            continue
    return ImageFont.load_default()


def _located(geos):
    out = []
    for g in geos or []:
        loc = (g or {}).get("location") or {}
        if loc.get("latitude") is None or loc.get("longitude") is None:
            continue
        out.append((float(loc["longitude"]), float(loc["latitude"]), g))
    return out


def _label(g):
    bits = [g.get("city"), g.get("country")]
    return ", ".join(str(x) for x in bits if x) or ""


def build_map(ips: list, geos: list) -> bytes:
    """PNG bytes; empty when no point has coordinates."""
    pts = _located(geos)
    if not pts:
        return b""
    img = Image.new("RGB", (W, H), SEA)
    d = ImageDraw.Draw(img)
    # graticule
    for lon in range(-180, 181, 30):
        x, _ = _xy(lon, 0)
        d.line([(x, 0), (x, H)], fill=GRID, width=1)
    for lat in range(-60, 61, 30):
        _, y = _xy(0, lat)
        d.line([(0, y), (W, y)], fill=GRID, width=1)
    # continents
    for poly in CONTINENTS:
        d.polygon([_xy(lon, lat) for lon, lat in poly], fill=LAND, outline=COAST)
    # markers
    f = _font(15)
    for i, (lon, lat, g) in enumerate(pts[:40], 1):
        x, y = _xy(lon, lat)
        r = 10
        d.ellipse([x - r, y - r, x + r, y + r], fill=MARK, outline=(255, 255, 255), width=2)
        tw = d.textlength(str(i), font=f)
        d.text((x - tw / 2, y - 8), str(i), fill=(255, 255, 255), font=f)
        lab = _label(g)
        if lab:
            d.text((x + 13, y - 8), lab[:38], fill=TEXT, font=f)
    # frame + caption
    d.rectangle([0, 0, W - 1, H - 1], outline=COAST, width=2)
    d.text((14, H - 24), "MailSleuth local schematic map - GeoLite2 coordinates, no external tiles",
           fill=TEXT, font=_font(13))
    out = io.BytesIO()
    img.save(out, "PNG", optimize=True)
    return out.getvalue()


def build_map_svg(ips: list, geos: list) -> str:
    """Optional crisp SVG variant (same schematic basemap)."""
    pts = _located(geos)
    if not pts:
        return ""
    parts = ['<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 600" role="img">',
             '<rect width="1200" height="600" fill="#e8f2f8"/>']
    for lon in range(-180, 181, 30):
        x, _ = _xy(lon, 0)
        parts.append(f'<line x1="{x:.1f}" y1="0" x2="{x:.1f}" y2="600" stroke="#becdd6"/>')
    for lat in range(-60, 61, 30):
        _, y = _xy(0, lat)
        parts.append(f'<line x1="0" y1="{y:.1f}" x2="1200" y2="{y:.1f}" stroke="#becdd6"/>')
    for poly in CONTINENTS:
        pts_s = " ".join(f"{_xy(lon, lat)[0]:.1f},{_xy(lon, lat)[1]:.1f}" for lon, lat in poly)
        parts.append(f'<polygon points="{pts_s}" fill="#cee0cd" stroke="#608068"/>')
    for i, (lon, lat, g) in enumerate(pts[:40], 1):
        x, y = _xy(lon, lat)
        parts.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="10" fill="#be1e2d" stroke="#fff" stroke-width="2"/>')
        parts.append(f'<text x="{x:.1f}" y="{y + 5:.1f}" text-anchor="middle" font-family="Arial" font-size="13" fill="#fff">{i}</text>')
        lab = _label(g).replace("&", "&amp;").replace("<", "&lt;")
        if lab:
            parts.append(f'<text x="{x + 14:.1f}" y="{y + 5:.1f}" font-family="Arial" font-size="14" fill="#1e2d37">{lab[:38]}</text>')
    parts.append('<text x="14" y="584" font-family="Arial" font-size="13" fill="#1e2d37">MailSleuth local schematic map - no external tiles</text>')
    parts.append("</svg>")
    return "".join(parts)
