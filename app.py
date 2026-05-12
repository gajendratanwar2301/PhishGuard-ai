import re, uuid, json
from datetime import datetime
from flask import Flask, render_template, request, jsonify, Response
from features import extract_features
import pickle

app = Flask(__name__)
app.secret_key = 'phishguard-secret-2024'

with open("model.pkl", "rb") as f:
    model = pickle.load(f)

scan_history = []

PHISH_KEYWORDS = ['login','verify','secure','bank','update','account',
                  'confirm','password','free','prize','winner','urgent',
                  'suspended','alert','validate','billing','signin','wallet']
SUSPICIOUS_TLDS   = ['.xyz','.biz','.info','.club','.top','.online','.site','.tk']
REDIRECT_PATTERNS = ['/f/','/r/','/go/','/click/','/redirect/','/out/','/link/','/track/']
KNOWN_REDIRECTORS  = ['dalerius.com','bit.do','rb.gy','cutt.ly','short.io',
                      'tinyurl.com','bit.ly','ow.ly','t2m.io','shorturl.at']

# ── Helpers ───────────────────────────────────────────────────────────────────

def get_domain(url):
    return re.sub(r'https?://', '', url.lower()).split('/')[0].split('?')[0]

def get_path(url):
    d = get_domain(url)
    return re.sub(r'https?://', '', url.lower()).replace(d, '', 1)

def is_redirect_url(url):
    u   = url.lower()
    d   = get_domain(u)
    path = get_path(u)
    if d in KNOWN_REDIRECTORS:          return True
    if any(p in path for p in REDIRECT_PATTERNS): return True
    if re.search(r'/\d{6,}', path):     return True  # /f/1852248104 pattern
    if re.search(r'/[a-z0-9]{6,10}$', path) and len(path) < 20: return True  # short hash
    return False

def follow_redirect(url, timeout=4):
    try:
        import requests as req
        resp = req.head(url, allow_redirects=True, timeout=timeout,
                        headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
        return resp.url
    except Exception:
        try:
            import requests as req
            resp = req.get(url, allow_redirects=True, timeout=timeout, stream=True,
                           headers={'User-Agent': 'Mozilla/5.0'})
            final = resp.url
            resp.close()
            return final
        except Exception:
            return url

def compute_risk_score(url, feat, proba, final_url=None, redirected=False):
    score = proba * 65
    u = url.lower()
    d = get_domain(u)
    if 'https' not in u:                score += 10
    if '@' in u:                         score += 12
    if re.search(r'\d{1,3}(\.\d{1,3}){3}', u): score += 15
    if d.count('.') > 2:                score += 7
    if any(t in d for t in SUSPICIOUS_TLDS): score += 9
    if u.count('-') > 2:                score += 5
    if len(url) > 100:                  score += 4
    if u.count('//') > 1:              score += 8
    matched = [kw for kw in PHISH_KEYWORDS if kw in u]
    score += min(len(matched) * 4, 16)
    if is_redirect_url(url):            score += 18   # redirect URLs are high risk
    if redirected and final_url and get_domain(final_url) != get_domain(url):
        score += 10   # redirected to different domain = more suspicious
    return min(100, round(score))

def get_threat_level(score):
    if score <= 20:  return {'label':'Low',      'color':'#00e87a','bg':'rgba(0,232,122,.1)',  'border':'rgba(0,232,122,.25)'}
    if score <= 50:  return {'label':'Medium',   'color':'#ffd000','bg':'rgba(255,208,0,.1)',  'border':'rgba(255,208,0,.25)'}
    if score <= 75:  return {'label':'High',     'color':'#ff8f00','bg':'rgba(255,143,0,.1)',  'border':'rgba(255,143,0,.25)'}
    return               {'label':'Critical',  'color':'#ff3d5a','bg':'rgba(255,61,90,.1)',   'border':'rgba(255,61,90,.25)'}

def get_detailed_analysis(url, final_url=None, redirected=False):
    u = url.lower()
    d = get_domain(u)
    matched_kw = [kw for kw in PHISH_KEYWORDS if kw in u]
    has_ip     = bool(re.search(r'\d{1,3}(\.\d{1,3}){3}', u))
    susp_tld   = next((t for t in SUSPICIOUS_TLDS if t in d), None)
    is_redir   = is_redirect_url(url)
    return {
        'ssl': {
            'label': 'SSL / HTTPS',
            'status': 'safe' if 'https' in u else 'danger',
            'detail': 'Encrypted HTTPS connection' if 'https' in u else 'No encryption — plain HTTP'
        },
        'domain': {
            'label': 'Domain Structure',
            'status': 'danger' if (d.count('.') > 2 or d.count('-') > 1) else 'safe',
            'detail': f'{d} | {d.count(".")} dot(s) | {d.count("-")} hyphen(s)'
        },
        'keywords': {
            'label': 'Keyword Analysis',
            'status': 'danger' if matched_kw else 'safe',
            'matches': matched_kw,
            'detail': ', '.join(matched_kw) if matched_kw else 'No suspicious keywords'
        },
        'tld': {
            'label': 'Domain Reputation',
            'status': 'warning' if susp_tld else 'safe',
            'detail': f'Suspicious TLD: {susp_tld}' if susp_tld else 'TLD appears normal'
        },
        'redirect': {
            'label': 'Redirect Detection',
            'status': 'danger' if is_redir else 'safe',
            'detail': f'Redirect/forwarder detected → {final_url}' if (is_redir and redirected and final_url) else
                      ('URL shortener/redirect pattern found' if is_redir else 'No redirect patterns detected')
        },
        'patterns': {
            'label': 'URL Patterns',
            'status': 'danger' if (has_ip or '@' in u or u.count('//') > 1) else 'safe',
            'detail': ' | '.join(filter(None, [
                'IP as domain' if has_ip else '',
                '@ symbol' if '@' in u else '',
                'Multiple //' if u.count('//') > 1 else '',
            ])) or 'No suspicious patterns'
        },
    }

def get_recommendations(result, analysis):
    recs = []
    if result == 'phishing':
        recs += ['Do NOT visit this URL under any circumstances',
                 'Report this URL to your security team',
                 'If already visited, change your passwords immediately',
                 'Run a malware scan on your device']
    if analysis['redirect']['status'] == 'danger':
        recs.append('This URL hides its true destination — always suspicious')
    if analysis['ssl']['status'] == 'danger':
        recs.append('Never enter credentials on non-HTTPS sites')
    if result == 'safe':
        recs += ['Verify domain spelling carefully before entering data',
                 'Enable 2FA on all important accounts']
    return recs[:6]

# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/', methods=['GET', 'POST'])
def home():
    result = risk_score = threat = analysis = scan_id = url = None
    final_url = None
    redirected = False
    recommendations = []

    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        if url:
            # Follow redirects for better analysis
            if is_redirect_url(url):
                final_url = follow_redirect(url)
                redirected = (final_url != url)

            # Analyze the more suspicious of original vs final URL
            feat  = extract_features(url)
            proba = float(model.predict_proba([feat])[0][1])

            if redirected and final_url:
                final_feat  = extract_features(final_url)
                final_proba = float(model.predict_proba([final_feat])[0][1])
                proba = max(proba, final_proba)  # take worst case

            pred       = 1 if proba >= 0.5 else 0
            result     = 'phishing' if pred == 1 else 'safe'
            risk_score = compute_risk_score(url, feat, proba, final_url, redirected)

            # Override: if redirect URL, treat as at least Medium risk
            if is_redirect_url(url) and risk_score < 40:
                risk_score = 42

            # Override result if risk score is high enough despite model
            if risk_score >= 60 and result == 'safe':
                result = 'phishing'

            threat          = get_threat_level(risk_score)
            analysis        = get_detailed_analysis(url, final_url, redirected)
            recommendations = get_recommendations(result, analysis)
            scan_id         = str(uuid.uuid4())[:8].upper()

            scan_history.insert(0, {
                'id': scan_id, 'url': url, 'result': result,
                'risk_score': risk_score, 'threat_level': threat['label'],
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M'),
                'proba': round(proba * 100, 1)
            })
            if len(scan_history) > 50:
                scan_history.pop()

    return render_template('index.html',
        url=url, result=result, risk_score=risk_score,
        threat=threat, analysis=analysis, scan_id=scan_id,
        final_url=final_url, redirected=redirected,
        recommendations=recommendations, recent=scan_history[:5])

@app.route('/dashboard')
def dashboard():
    total = len(scan_history)
    safe_count  = sum(1 for s in scan_history if s['result'] == 'safe')
    phish_count = total - safe_count
    avg_risk    = round(sum(s['risk_score'] for s in scan_history) / total, 1) if total else 0
    return render_template('dashboard.html',
        history=scan_history[:20], total=total,
        safe_count=safe_count, phish_count=phish_count, avg_risk=avg_risk)

@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({'error': "Missing 'url'"}), 400
    url   = data['url'].strip()
    feat  = extract_features(url)
    proba = float(model.predict_proba([feat])[0][1])
    final_url  = follow_redirect(url) if is_redirect_url(url) else url
    redirected = final_url != url
    if redirected:
        fp    = extract_features(final_url)
        proba = max(proba, float(model.predict_proba([fp])[0][1]))
    pred       = 1 if proba >= 0.5 else 0
    result     = 'phishing' if pred == 1 else 'safe'
    risk_score = compute_risk_score(url, feat, proba, final_url, redirected)
    if is_redirect_url(url) and risk_score < 40:
        risk_score = 42
    if risk_score >= 60 and result == 'safe':
        result = 'phishing'
    threat = get_threat_level(risk_score)
    return jsonify({'url': url, 'final_url': final_url, 'result': result,
                    'risk_score': risk_score, 'threat_level': threat['label'],
                    'confidence': round(proba * 100, 1)})

@app.route('/report/<scan_id>')
def download_report(scan_id):
    entry = next((s for s in scan_history if s['id'] == scan_id), None)
    if not entry:
        return "Report not found", 404
    lines = [
        "=" * 60,
        "   PHISHGUARD AI — SECURITY INVESTIGATION REPORT",
        "=" * 60,
        f"Scan ID:      {entry['id']}",
        f"Timestamp:    {entry['timestamp']}",
        f"Analyzed URL: {entry['url']}",
        "=" * 60,
        f"VERDICT:      {'PHISHING DETECTED' if entry['result']=='phishing' else 'SAFE'}",
        f"RISK SCORE:   {entry['risk_score']}/100",
        f"THREAT LEVEL: {entry['threat_level']}",
        f"CONFIDENCE:   {entry['proba']}%",
        "=" * 60,
        "RECOMMENDATIONS:",
        "  - Never share credentials via links in emails/SMS",
        "  - Verify domain spelling before entering sensitive data",
        "  - Enable 2FA on all important accounts",
        "  - Report phishing: report@phishing.gov.in",
        "=" * 60,
        "Generated by PhishGuard AI | For educational purposes",
    ]
    return Response("\n".join(lines), mimetype='text/plain',
        headers={"Content-Disposition": f"attachment;filename=PhishGuard_Report_{scan_id}.txt"})

if __name__ == '__main__':
    app.run(debug=True)