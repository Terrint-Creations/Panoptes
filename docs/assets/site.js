(() => {
  "use strict";
  const REPO = "Terrint-Creations/Panoptes";

  // Mobile menu
  const btn = document.querySelector(".menu-btn");
  const nav = document.querySelector(".nav");
  if (btn && nav) {
    btn.addEventListener("click", () => {
      const open = nav.classList.toggle("open");
      btn.setAttribute("aria-expanded", String(open));
    });
    nav.addEventListener("click", e => { if (e.target.tagName === "A") nav.classList.remove("open"); });
  }

  // Tabs (desktop / terminal)
  document.querySelectorAll("[role=tablist]").forEach(list => {
    const tabs = [...list.querySelectorAll("[role=tab]")];
    tabs.forEach(tab => tab.addEventListener("click", () => {
      tabs.forEach(t => {
        const on = t === tab;
        t.setAttribute("aria-selected", String(on));
        document.getElementById(t.getAttribute("aria-controls")).hidden = !on;
      });
    }));
  });

  // Latest release number
  const vEls = document.querySelectorAll("[data-version]");
  if (vEls.length) {
    fetch(`https://api.github.com/repos/${REPO}/releases/latest`, { headers: { Accept: "application/vnd.github+json" } })
      .then(r => r.ok ? r.json() : null)
      .then(d => { if (d && d.tag_name) vEls.forEach(el => { el.textContent = d.tag_name; }); })
      .catch(() => {});
  }

  // The hundred eyes
  const canvas = document.querySelector("canvas.eyes");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const still = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  let W = 0, H = 0, dpr = 1, eyes = [], mouse = null, running = false, visible = true;

  function layout() {
    const r = canvas.getBoundingClientRect();
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    W = r.width; H = r.height;
    canvas.width = Math.round(W * dpr); canvas.height = Math.round(H * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const cell = W < 600 ? 64 : 84;
    eyes = [];
    let seed = 7;
    const rnd = () => (seed = (seed * 16807) % 2147483647) / 2147483647;
    for (let y = cell * 0.6; y < H + cell; y += cell * 0.82) {
      for (let x = cell * 0.5 + ((y / cell) % 2 ? cell / 2 : 0); x < W + cell; x += cell) {
        const s = 0.55 + rnd() * 0.7;
        eyes.push({
          x: x + (rnd() - 0.5) * cell * 0.4,
          y: y + (rnd() - 0.5) * cell * 0.3,
          w: 30 * s, h: 13 * s,
          rest: 0.25 + rnd() * 0.75,
          open: 0.25 + rnd() * 0.75,
          blinkAt: performance.now() + rnd() * 9000,
          blink: 0,
          lx: 0, ly: 0,
        });
      }
    }
  }

  function draw(t) {
    ctx.clearRect(0, 0, W, H);
    for (const e of eyes) {
      // blinking
      if (!still && t > e.blinkAt) { e.blink = 1; e.blinkAt = t + 3500 + Math.random() * 9000; }
      if (e.blink > 0) e.blink = Math.max(0, e.blink - 0.09);
      const near = mouse ? Math.max(0, 1 - Math.hypot(mouse.x - e.x, mouse.y - e.y) / 260) : 0;
      const target = Math.min(1, e.rest + near * 0.9);
      e.open += (target - e.open) * 0.08;
      const lid = e.open * (1 - Math.sin(e.blink * Math.PI));
      // gaze
      let gx = 0, gy = 0;
      if (mouse) {
        const dx = mouse.x - e.x, dy = mouse.y - e.y, d = Math.hypot(dx, dy) || 1;
        const k = Math.min(1, d / 120);
        gx = dx / d * e.w * 0.2 * k; gy = dy / d * e.h * 0.35 * k;
      }
      e.lx += (gx - e.lx) * 0.12; e.ly += (gy - e.ly) * 0.12;

      const hw = e.w / 2, hh = e.h * lid;
      ctx.save();
      ctx.beginPath();
      ctx.moveTo(e.x - hw, e.y);
      ctx.quadraticCurveTo(e.x, e.y - hh * 2, e.x + hw, e.y);
      ctx.quadraticCurveTo(e.x, e.y + hh * 2, e.x - hw, e.y);
      ctx.closePath();
      ctx.strokeStyle = `rgba(212,160,23,${0.28 + near * 0.6})`;
      ctx.lineWidth = 1.1;
      ctx.stroke();
      if (lid > 0.06) {
        ctx.clip();
        const ir = e.h * 0.78;
        ctx.beginPath();
        ctx.arc(e.x + e.lx, e.y + e.ly, ir, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(212,160,23,${0.35 + near * 0.55})`;
        ctx.fill();
        ctx.beginPath();
        ctx.arc(e.x + e.lx, e.y + e.ly, ir * 0.45, 0, Math.PI * 2);
        ctx.fillStyle = "#0f0e0c";
        ctx.fill();
      }
      ctx.restore();
    }
  }

  function loop(t) {
    if (!running) return;
    draw(t);
    requestAnimationFrame(loop);
  }
  function start() {
    if (still) { draw(performance.now()); return; }
    if (!running && visible) { running = true; requestAnimationFrame(loop); }
  }

  const hero = canvas.parentElement;
  hero.addEventListener("pointermove", e => {
    const r = canvas.getBoundingClientRect();
    mouse = { x: e.clientX - r.left, y: e.clientY - r.top };
    if (still) draw(performance.now());
  });
  hero.addEventListener("pointerleave", () => { mouse = null; if (still) draw(performance.now()); });
  new IntersectionObserver(([en]) => {
    visible = en.isIntersecting;
    if (visible) start(); else running = false;
  }).observe(canvas);
  document.addEventListener("visibilitychange", () => { if (document.hidden) running = false; else start(); });
  let rt;
  window.addEventListener("resize", () => { clearTimeout(rt); rt = setTimeout(() => { layout(); start(); }, 120); });
  layout();
  start();
})();
