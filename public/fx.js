// Decorative matrix rain behind the login detective. Purely visual: skipped for
// reduced-motion users (columns stay static) and generated once at load.
const rain = document.querySelector('.matrix-rain');
if (rain && !rain.childElementCount) {
  const glyphs = '010100111010ABCDEF0123456789abcdef';
  const cols = 16;
  for (let i = 0; i < cols; i++) {
    const col = document.createElement('i');
    let s = '';
    for (let j = 0; j < 48; j++) s += glyphs[(Math.random() * glyphs.length) | 0];
    col.textContent = s;
    col.style.left = ((i + 0.5) * 100 / cols).toFixed(2) + '%';
    col.style.animationDuration = (5 + Math.random() * 7).toFixed(2) + 's';
    col.style.animationDelay = (-Math.random() * 12).toFixed(2) + 's';
    col.style.opacity = (0.22 + Math.random() * 0.4).toFixed(2);
    rain.appendChild(col);
  }
}

// Lens glow follower: decorative only, disabled on touch devices and for reduced motion.
const lens = document.getElementById('lens');
if (lens && matchMedia('(hover:hover) and (pointer:fine)').matches && !matchMedia('(prefers-reduced-motion:reduce)').matches) {
  lens.hidden = false; let x = -100, y = -100, raf = 0;
  addEventListener('pointermove', e => { x = e.clientX; y = e.clientY; if (!raf) raf = requestAnimationFrame(() => { lens.style.transform = `translate3d(${x}px,${y}px,0)`; raf = 0; }); }, { passive: true });
  addEventListener('pointerdown', () => { lens.classList.add('zap'); setTimeout(() => lens.classList.remove('zap'), 350); });
  document.addEventListener('mouseleave', () => { lens.hidden = true; });
  document.addEventListener('mouseenter', () => { lens.hidden = false; });
}
