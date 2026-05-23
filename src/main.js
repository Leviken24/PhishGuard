import './style.css'

// Canvas Background Animation
const canvas = document.getElementById('cyber-bg');
if (canvas) {
  const ctx = canvas.getContext('2d');
  let width = canvas.width = window.innerWidth;
  let height = canvas.height = window.innerHeight;

  const particles = [];
  const particleCount = 70;
  const maxDistance = 110;

  class Particle {
    constructor() {
      this.x = Math.random() * width;
      this.y = Math.random() * height;
      this.vx = (Math.random() - 0.5) * 0.35;
      this.vy = (Math.random() - 0.5) * 0.35;
      this.radius = Math.random() * 1.5 + 0.8;
    }

    update() {
      this.x += this.vx;
      this.y += this.vy;

      if (this.x < 0 || this.x > width) this.vx *= -1;
      if (this.y < 0 || this.y > height) this.vy *= -1;
    }

    draw() {
      ctx.beginPath();
      ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(0, 229, 255, 0.35)';
      ctx.fill();
    }
  }

  function initParticles() {
    particles.length = 0;
    for (let i = 0; i < particleCount; i++) {
      particles.push(new Particle());
    }
  }

  function connectParticles() {
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const dx = particles[i].x - particles[j].x;
        const dy = particles[i].y - particles[j].y;
        const dist = Math.sqrt(dx * dx + dy * dy);

        if (dist < maxDistance) {
          const alpha = (1 - dist / maxDistance) * 0.12;
          ctx.strokeStyle = `rgba(0, 229, 255, ${alpha})`;
          ctx.lineWidth = 0.6;
          ctx.beginPath();
          ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(particles[j].x, particles[j].y);
          ctx.stroke();
        }
      }
    }
  }

  function animate() {
    ctx.clearRect(0, 0, width, height);

    particles.forEach(p => {
      p.update();
      p.draw();
    });

    connectParticles();
    requestAnimationFrame(animate);
  }

  window.addEventListener('resize', () => {
    width = canvas.width = window.innerWidth;
    height = canvas.height = window.innerHeight;
    initParticles();
  });

  initParticles();
  animate();
}


// Tab Switching Logic
const tabs = document.querySelectorAll('.tab-btn');
const tabContents = document.querySelectorAll('.tab-content');

tabs.forEach(tab => {
  tab.addEventListener('click', () => {
    const target = tab.dataset.tab;
    tabs.forEach(t => t.classList.remove('active'));
    tabContents.forEach(c => c.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById(`${target}-tab`).classList.add('active');
  });
});

// URL Scanner
const scanUrlBtn = document.getElementById('scan-url-btn');
const urlInput   = document.getElementById('url-input');
const urlResult  = document.getElementById('url-result');

scanUrlBtn.addEventListener('click', () => {
  const url = urlInput.value.trim();
  if (!url) { showWarn(urlResult, 'Please enter a URL to scan.'); return; }
  showLoading(urlResult);
  setTimeout(() => renderResult(urlResult, scanURL(url)), 1600);
});

// Message Analyzer
const scanMsgBtn = document.getElementById('scan-msg-btn');
const msgInput   = document.getElementById('message-input');
const msgResult  = document.getElementById('msg-result');

scanMsgBtn.addEventListener('click', () => {
  const text = msgInput.value.trim();
  if (!text) { showWarn(msgResult, 'Please paste a message to analyze.'); return; }
  showLoading(msgResult);
  setTimeout(() => renderResult(msgResult, scanMessage(text)), 1900);
});

// ─── URL SCANNER ENGINE ──────────────────────────────────────────────────────

function scanURL(raw) {
  let score = 0;
  const flags = [];

  let urlObj;
  try {
    urlObj = new URL(/^https?:\/\//i.test(raw) ? raw : `https://${raw}`);
  } catch {
    return { is_scam: true, risk_score: 90, category: 'Invalid URL',
      explanation: 'The input is not a parseable URL — malformed links are a common obfuscation tactic.',
      recommended_action: 'Do not visit. Discard and report to your email provider.' };
  }

  const host = urlObj.hostname.toLowerCase();
  const path = urlObj.pathname.toLowerCase();
  const full = raw.toLowerCase();

  // ── Brand impersonation / typosquatting ──
  const brands = ['paypal','amazon','google','facebook','apple','netflix','microsoft','instagram',
    'whatsapp','bank','sbi','hdfc','icici','axis','paytm','phonepe','gpay','irs','gov','support'];
  const typoVariants = {
    paypal: /p[a4]yp[a4]l|paypla|paypa1/,
    amazon: /am[a@]zon|amaz0n/,
    google: /g[o0]{2}gle|go0gle|gooogle/,
    microsoft: /micros[o0]ft|micr0soft/,
    apple:  /[a@]pple|app1e/,
  };

  for (const [brand, regex] of Object.entries(typoVariants)) {
    if (regex.test(host) && !host.endsWith(`${brand}.com`)) {
      score += 35; flags.push(`Typosquatting brand '${brand}'`);
    }
  }

  brands.forEach(b => {
    if (host.includes(b) && !host.endsWith(`${b}.com`) && !host.endsWith(`${b}.gov`)) {
      if (!flags.some(f => f.includes('Typosquat'))) {
        score += 20; flags.push(`Brand name '${b}' used in suspicious domain`);
      }
    }
  });

  // ── IP-based hostname ──
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) {
    score += 45; flags.push('IP address used as domain — classic phishing tactic');
  }

  // ── Punycode / homograph ──
  if (host.includes('xn--')) {
    score += 45; flags.push('Punycode/IDN homograph attack detected');
  }

  // ── Suspicious TLDs ──
  const badTLDs = ['.xyz','.tk','.ga','.cf','.ml','.party','.date','.top','.win','.click',
    '.loan','.gq','.pw','.country','.stream','.download','.science','.work'];
  if (badTLDs.some(t => host.endsWith(t))) {
    score += 30; flags.push(`High-risk TLD: ${host.split('.').pop()}`);
  }

  // ── URL shortener ──
  const shorteners = ['bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd','buff.ly','adf.ly',
    'shorte.st','v.gd','bc.vc','rb.gy','cutt.ly','tiny.cc'];
  if (shorteners.some(s => host === s || host.endsWith(`.${s}`))) {
    score += 25; flags.push('Shortened URL — destination is hidden');
  }

  // ── Excessive subdomains ──
  const subCount = host.split('.').length - 2;
  if (subCount >= 3) { score += 20; flags.push(`Excessive subdomains (${subCount}) used to fake legitimacy`); }

  // ── Sensitive keywords in path ──
  const pathKeywords = ['login','signin','verify','account','update','secure','bank','confirm',
    'password','otp','auth','wallet','checkout','reset','recover','unlock','suspend'];
  pathKeywords.forEach(k => {
    if (path.includes(k)) { score += 12; flags.push(`Sensitive keyword in path: '${k}'`); }
  });

  // ── Random-looking domain (high consonant clusters) ──
  const domainPart = host.split('.')[0];
  if (domainPart.length > 12 && /[^aeiou]{5,}/.test(domainPart)) {
    score += 15; flags.push('Domain looks randomly generated (high consonant density)');
  }

  // ── Long URL (obfuscation) ──
  if (raw.length > 100) { score += 10; flags.push('Abnormally long URL — common obfuscation technique'); }

  // ── Non-HTTPS ──
  if (urlObj.protocol === 'http:') { score += 20; flags.push('Non-HTTPS connection — data transmitted in plaintext'); }

  // ── Redirect params ──
  if (/redirect|return_url|next=|goto=|url=|link=/.test(full)) {
    score += 15; flags.push('Open redirect parameter detected in URL');
  }

  // ── Multiple @ signs (credential stuffing trick) ──
  if ((raw.match(/@/g) || []).length > 1) {
    score += 35; flags.push('Multiple @ symbols — browser may ignore embedded fake credentials');
  }

  // Cap at 100
  score = Math.min(score, 100);
  const category = classifyURLCategory(flags);
  return buildResult(score, category, flags, 'url');
}

// ─── MESSAGE SCANNER ENGINE ──────────────────────────────────────────────────

function scanMessage(text) {
  let score = 0;
  const flags = [];
  const t = text.toLowerCase();

  // ── Urgency / fear ──
  const urgency = ['urgent','immediately','right now','limited time','act now','expires today',
    'last chance','final notice','time sensitive','within 24 hours','hours remaining'];
  const foundUrgency = urgency.filter(w => t.includes(w));
  if (foundUrgency.length) { score += foundUrgency.length * 12; flags.push(`Urgency triggers: "${foundUrgency.slice(0,3).join('", "')}"`); }

  // ── Fear / threats ──
  const fear = ['account suspended','account blocked','legal action','arrested','fined','reported to police',
    'warrant','authorities','deactivated','terminated','deleted'];
  const foundFear = fear.filter(w => t.includes(w));
  if (foundFear.length) { score += foundFear.length * 15; flags.push(`Fear/threat language: "${foundFear.slice(0,2).join('", "')}"`); }

  // ── Rewards / lotteries ──
  const reward = ['you have won','congratulations','selected winner','prize','lottery','reward','jackpot',
    'free gift','claim now','you are a winner','lucky winner'];
  const foundReward = reward.filter(w => t.includes(w));
  if (foundReward.length) { score += foundReward.length * 14; flags.push(`Reward/lottery bait: "${foundReward.slice(0,2).join('", "')}"`); }

  // ── OTP / banking scams ──
  const otp = ['share your otp','enter your otp','do not share otp','your otp is','verification code',
    'pin number','cvv','card number','net banking','bank account number'];
  const foundOtp = otp.filter(w => t.includes(w));
  if (foundOtp.length) { score += foundOtp.length * 18; flags.push(`OTP/banking solicitation: "${foundOtp.slice(0,2).join('", "')}"`); }

  // ── Investment scams ──
  const invest = ['guaranteed return','double your money','profit of','risk free','100% return',
    'investment scheme','crypto profit','passive income','make money fast','ponzi'];
  const foundInvest = invest.filter(w => t.includes(w));
  if (foundInvest.length) { score += foundInvest.length * 15; flags.push(`Investment scam signals: "${foundInvest.slice(0,2).join('", "')}"`); }

  // ── Job scams ──
  const job = ['work from home','part time earning','earn daily','per day income','data entry job',
    'easy job','no experience required','weekly salary','reseller job','referral income'];
  const foundJob = job.filter(w => t.includes(w));
  if (foundJob.length) { score += foundJob.length * 12; flags.push(`Fake job scam patterns: "${foundJob.slice(0,2).join('", "')}"`); }

  // ── Impersonation ──
  const impersonate = ['rbi','reserve bank','income tax','tax department','customs','amazon customer service',
    'google team','microsoft support','apple support','government of india','police','cbi','interpol'];
  const foundImp = impersonate.filter(w => t.includes(w));
  if (foundImp.length) { score += foundImp.length * 20; flags.push(`Authority impersonation: "${foundImp.slice(0,2).join('", "')}"`); }

  // ── Fake support ──
  const support = ['call this number','call us immediately','customer care number','helpline',
    'toll free','support team is waiting','remote access','allow access to your device'];
  const foundSupport = support.filter(w => t.includes(w));
  if (foundSupport.length) { score += foundSupport.length * 14; flags.push(`Fake support/helpline: "${foundSupport.slice(0,2).join('", "')}"`); }

  // ── Giveaway scams ──
  const giveaway = ['free iphone','free recharge','free data','gift card','amazon voucher',
    'jio recharge','paytm cashback','google pay','phonepe offer'];
  const foundGive = giveaway.filter(w => t.includes(w));
  if (foundGive.length) { score += foundGive.length * 13; flags.push(`Giveaway scam: "${foundGive.slice(0,2).join('", "')}"`); }

  // ── Obfuscation tactics ──
  const capsRatio = (text.match(/[A-Z]/g) || []).length / Math.max(text.length, 1);
  if (capsRatio > 0.4 && text.length > 15) { score += 10; flags.push('Excessive capitalization (shouting/urgency obfuscation)'); }

  // ── Suspicious URL embedded ──
  const urlMatch = text.match(/https?:\/\/[^\s]+/);
  if (urlMatch) {
    const urlResult = scanURL(urlMatch[0]);
    if (urlResult.risk_score >= 40) {
      score += Math.round(urlResult.risk_score * 0.4);
      flags.push(`Embedded suspicious URL: ${urlMatch[0].slice(0, 50)}${urlMatch[0].length > 50 ? '…' : ''}`);
    }
  }

  // ── Bare phone numbers (asking to call) ──
  if (/(\+91|0)?[6-9]\d{9}/.test(text) && (t.includes('call') || t.includes('whatsapp') || t.includes('contact'))) {
    score += 15; flags.push('Phone number combined with call-to-action');
  }

  score = Math.min(score, 100);
  const category = classifyMessageCategory(flags);
  return buildResult(score, category, flags, 'message');
}

// ─── HELPERS ─────────────────────────────────────────────────────────────────

function classifyURLCategory(flags) {
  const f = flags.join(' ').toLowerCase();
  if (f.includes('typosquat') || f.includes('impersonat')) return 'Brand Impersonation';
  if (f.includes('ip address')) return 'Direct IP Phishing';
  if (f.includes('punycode') || f.includes('homograph')) return 'Homograph Attack';
  if (f.includes('shortened')) return 'Obfuscated Redirect';
  if (f.includes('otp') || f.includes('login') || f.includes('verify')) return 'Credential Harvesting';
  if (f.includes('redirect')) return 'Open Redirect Exploit';
  if (f.includes('tld')) return 'Suspicious Domain';
  return 'Suspicious URL';
}

function classifyMessageCategory(flags) {
  const f = flags.join(' ').toLowerCase();
  if (f.includes('impersonation')) return 'Authority Impersonation';
  if (f.includes('otp') || f.includes('banking')) return 'Banking / OTP Fraud';
  if (f.includes('investment') || f.includes('crypto')) return 'Investment Scam';
  if (f.includes('job') || f.includes('earn')) return 'Fake Job Scam';
  if (f.includes('lottery') || f.includes('reward') || f.includes('giveaway')) return 'Lottery / Giveaway Scam';
  if (f.includes('support') || f.includes('helpline')) return 'Fake Customer Support';
  if (f.includes('fear') || f.includes('threat')) return 'Fear / Threat Scam';
  if (f.includes('urgency')) return 'Urgency Manipulation';
  return 'Spam / Phishing';
}

function buildResult(score, category, flags, type) {
  const isScam = score >= 30;
  let explanation = flags.length
    ? `Detected ${flags.length} suspicious signal${flags.length > 1 ? 's' : ''}: ${flags[0]}${flags.length > 1 ? ` (+${flags.length - 1} more)` : ''}.`
    : type === 'url'
      ? 'No immediate threat signatures found in this URL.'
      : 'No spam or scam patterns detected in this message.';

  let action;
  if (score >= 70) action = 'Do NOT proceed. Block the sender and report as phishing immediately.';
  else if (score >= 45) action = 'Exercise extreme caution. Do not click links or share personal data.';
  else if (score >= 20) action = 'Proceed carefully. Verify the source independently before taking action.';
  else action = 'Appears safe, but always verify the sender before sharing sensitive information.';

  return { is_scam: isScam, risk_score: score, category, explanation, recommended_action: action, _flags: flags };
}

// ─── UI RENDERING ─────────────────────────────────────────────────────────────

function showWarn(el, msg) {
  el.classList.remove('hidden', 'safe', 'warning', 'danger');
  el.classList.add('warning');
  el.innerHTML = `<div class="result-grid"><div class="result-score-gauge">
    <div class="score-circle warning-color"><span class="score-num">!</span><span class="score-lbl">Alert</span></div>
  </div><div class="result-details"><div class="result-header">
    <h4>Input Required</h4><span class="badge-warning">WARN</span>
  </div><div class="result-body-field"><p>${msg}</p></div></div></div>`;
}

function showLoading(el) {
  el.classList.remove('hidden', 'safe', 'warning', 'danger');
  el.innerHTML = `<div class="loading-spinner">Running threat analysis…</div>`;
}

function renderResult(el, r) {
  const level = r.risk_score >= 60 ? 'danger' : r.risk_score >= 25 ? 'warning' : 'safe';
  const scoreColorClass = `${level}-color`;
  const badgeClass = `badge-${level}`;
  const badgeLabel = level === 'danger' ? 'SCAM' : level === 'warning' ? 'SUSPICIOUS' : 'SAFE';

  const flagsHTML = r._flags && r._flags.length
    ? `<div class="result-body-field">
        <strong>Detection signals</strong>
        <ul class="flag-list">${r._flags.map(f => `<li>${f}</li>`).join('')}</ul>
      </div>`
    : '';

  el.classList.remove('hidden', 'safe', 'warning', 'danger');
  el.classList.add(level);
  el.innerHTML = `
    <div class="result-grid">
      <div class="result-score-gauge">
        <div class="score-circle ${scoreColorClass}">
          <span class="score-num">${r.risk_score}</span>
          <span class="score-lbl">Risk Score</span>
        </div>
      </div>
      <div class="result-details">
        <div class="result-header">
          <h4>${r.category}</h4>
          <span class="${badgeClass}">${badgeLabel}</span>
        </div>
        <div class="result-body-field">
          <strong>Explanation</strong>
          <p>${r.explanation}</p>
        </div>
        ${flagsHTML}
        <div class="result-body-field">
          <strong>Recommended Action</strong>
          <p>${r.recommended_action}</p>
        </div>
      </div>
    </div>
  `;
}


