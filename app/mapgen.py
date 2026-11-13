"""Map stitch (OSM tiles via Pillow) + MapGlot delegate (compat)."""
import io, os, math, requests
from PIL import Image, ImageDraw, ImageFont
from .mapglot import reverse as mapglot_reverse

TILE = 256; N = 5  # 5x5 tiles ~ 5cm at zoom 5

def _tile_url(z, x, y):
    return f"https://tile.openstreetmap.org/{z}/{x}/{y}.png"

def build_map(ips: list, geos: list) -> bytes:
    # Simplified: mid-point of located IPs, render tiles + numbered markers.
    pts = [g["location"] for g in geos if g.get("location") and g["location"].get("latitude") is not None]
    if not pts: return b""
    lat = sum(p["latitude"] for p in pts) / len(pts)
    lon = sum(p["longitude"] for p in pts) / len(pts)
    z = 8; n = 2 ** z
    xt = int((lon + 180.0) / 360.0 * n); yt = int((1.0 - math.log(math.tan(math.radians(lat)) + 1/math.cos(math.radians(lat))) / math.pi) / 2.0 * n)
    img = Image.new("RGB", (TILE * N, TILE * N), "white")
    for dy in range(N):
        for dx in range(N):
            try:
                r = requests.get(_tile_url(z, xt + dx - N//2, yt + dy - N//2),
                                 headers={"User-Agent": "MailSleuth/1.0"}, timeout=8)
                img.paste(Image.open(io.BytesIO(r.content)).convert("RGB"), (dx*TILE, dy*TILE))
            except Exception: pass
    d = ImageDraw.Draw(img)
    for i, p in enumerate(pts[:N*N]):
        # project to pixel offset from center tile
        x = TILE*N//2 + int((p["longitude"] - lon) * 8) - 10
        y = TILE*N//2 + int((lat - p["latitude"]) * 8) - 10
        d.ellipse([x, y, x+20, y+20], fill="red", outline="white")
        d.text((x+6, y+4), str(i+1), fill="white")
    d.ellipse([TILE*N//2-10, TILE*N//2-10, TILE*N//2+10, TILE*N//2+10], fill="red", outline="white")
    out = io.BytesIO(); img.save(out, "PNG"); return out.getvalue()

def reverse_geocode(lat: float, lon: float, api_key: str, base: str = None, lang: str = "en") -> str:
    """Compat wrapper: addr logit (None-safe). See app/mapglot.reverse for full 100% port."""
    if base: os.environ["MAPGLOT_BASE"] = base
    r = mapglot_reverse(lat, lon, api_key, lang)
    return (r or {}).get("address") or ""
