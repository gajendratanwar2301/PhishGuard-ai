// Loading state
const form = document.getElementById('scanForm');
const btn  = document.getElementById('scanBtn');
const inp  = document.getElementById('urlInput');
const bar  = document.getElementById('scanBar');

if (inp) inp.focus();

if (form) {
  form.addEventListener('submit', e => {
    if (!inp.value.trim()) { e.preventDefault(); inp.focus(); return; }
    btn.classList.add('loading');
    btn.disabled = true;
    if (bar) { bar.classList.add('active'); }
  });
}

// Scroll result into view
const rc = document.getElementById('resultCard');
if (rc) setTimeout(() => rc.scrollIntoView({ behavior:'smooth', block:'nearest' }), 300);

// Animated counters
function animateCount(el, target, suffix='', duration=2000) {
  let start = 0;
  const step = target / (duration / 16);
  const timer = setInterval(() => {
    start = Math.min(start + step, target);
    el.textContent = Math.floor(start).toLocaleString() + suffix;
    if (start >= target) clearInterval(timer);
  }, 16);
}

const statObserver = new IntersectionObserver(entries => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      entry.target.querySelectorAll('[data-count]').forEach(el => {
        animateCount(el, +el.dataset.count, el.dataset.suffix || '');
      });
      statObserver.unobserve(entry.target);
    }
  });
}, { threshold: 0.3 });

document.querySelectorAll('.stats-grid').forEach(g => statObserver.observe(g));

// Scroll reveal
const revealObserver = new IntersectionObserver(entries => {
  entries.forEach((entry, i) => {
    if (entry.isIntersecting) {
      setTimeout(() => entry.target.classList.add('visible'), i * 80);
      revealObserver.unobserve(entry.target);
    }
  });
}, { threshold: 0.12 });

document.querySelectorAll('.step-card, .type-card, .tip-card').forEach(el => {
  revealObserver.observe(el);
});

// Smooth nav active state
const sections = document.querySelectorAll('section[id]');
const navLinks = document.querySelectorAll('.nav-links a[href^="#"]');
window.addEventListener('scroll', () => {
  let cur = '';
  sections.forEach(s => { if (window.scrollY >= s.offsetTop - 100) cur = s.id; });
  navLinks.forEach(a => {
    a.classList.toggle('active', a.getAttribute('href') === '#' + cur);
  });
}, { passive: true });

// Hamburger menu
const ham = document.getElementById('hamburger');
const navL = document.querySelector('.nav-links');
if (ham && navL) {
  ham.addEventListener('click', () => {
    const open = navL.style.display === 'flex';
    navL.style.cssText = open
      ? ''
      : 'display:flex;flex-direction:column;position:fixed;top:64px;left:0;right:0;background:rgba(4,8,15,.97);padding:16px;gap:4px;border-bottom:1px solid rgba(255,255,255,.07)';
    ham.classList.toggle('open', !open);
  });
}

// ── Sound Effects ─────────────────────────────────────────────────────────────
function getAudioCtx() {
  return new (window.AudioContext || window.webkitAudioContext)();
}

function playSafeSound() {
  try {
    const ctx = getAudioCtx();
    // Pleasant ascending chime: C-E-G chord
    [261.63, 329.63, 392.00, 523.25].forEach((freq, i) => {
      const osc  = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.connect(gain); gain.connect(ctx.destination);
      osc.type      = 'sine';
      osc.frequency.value = freq;
      const t = ctx.currentTime + i * 0.1;
      gain.gain.setValueAtTime(0, t);
      gain.gain.linearRampToValueAtTime(0.18, t + 0.05);
      gain.gain.exponentialRampToValueAtTime(0.001, t + 0.5);
      osc.start(t); osc.stop(t + 0.5);
    });
    // Speech after chime
    setTimeout(() => {
      const msg = new SpeechSynthesisUtterance("It's clean bro!");
      msg.rate = 0.92; msg.pitch = 1.2; msg.volume = 1;
      window.speechSynthesis.speak(msg);
    }, 600);
  } catch(e) { console.warn('Sound error:', e); }
}

function playPhishingSound() {
  try {
    const ctx  = getAudioCtx();
    const dur  = 1.8;
    // Siren: oscillate between 600Hz and 1200Hz
    const osc  = ctx.createOscillator();
    const lfo  = ctx.createOscillator();
    const lfog = ctx.createGain();
    const gain = ctx.createGain();
    lfo.connect(lfog); lfog.connect(osc.frequency);
    osc.connect(gain); gain.connect(ctx.destination);
    osc.type      = 'sawtooth';
    osc.frequency.value = 900;
    lfo.type      = 'sine';
    lfo.frequency.value = 3;
    lfog.gain.value = 300;
    gain.gain.setValueAtTime(0.22, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + dur);
    osc.start(ctx.currentTime); osc.stop(ctx.currentTime + dur);
    lfo.start(ctx.currentTime); lfo.stop(ctx.currentTime + dur);
    // Speech after siren
    setTimeout(() => {
      const msg = new SpeechSynthesisUtterance("Warning! Phishing detected! Do not visit this site!");
      msg.rate = 1.05; msg.pitch = 0.85; msg.volume = 1;
      window.speechSynthesis.speak(msg);
    }, 700);
  } catch(e) { console.warn('Sound error:', e); }
}

// Auto-play on result
const resultCard = document.getElementById('resultCard');
if (resultCard) {
  // Small delay so page renders first
  setTimeout(() => {
    if (resultCard.querySelector('.r-safe'))     playSafeSound();
    else if (resultCard.querySelector('.r-phishing')) playPhishingSound();
  }, 500);
}
