import re, uuid, json
from datetime import datetime
from flask import Flask, render_template, request, jsonify, Response
from features import extract_features
import pickle

app = Flask(__name__)
app.secret_key = 'phishguard-secret-2024'

with open("model.pkl", "rb") as f:
    model = pickle.load(f)

# In-memory scan history (max 50)
scan_history = []

PHISH_KEYWORDS = ['login','verify','secure','bank','update','account',
                  'confirm','password','free','prize','winner','urgent',
                  'suspended','alert','validate','billing','signin','wallet']
SUSPICIOUS_TLDS = ['.xyz','.biz','.info','.club','.top','.online','.site','.tk']

# ── Analysis Helpers ─────────────────────────────────────────────────────────

def get_domain(url):
    return re.sub(r'https?://', '', url.lower()).split('/')[0].split('?')[0]

def compute_risk_score(url, feat, proba):
    """Combine model probability with rule-based bonuses → 0-100."""
    score = proba * 65
    u = url.lower()
    d = get_domain(u)
    if 'https' not in u:               score += 10
    if '@' in u:                        score += 12
    if re.search(r'\d{1,3}(\.\d{1,3}){3}', u): score += 15
    if d.count('.') > 2:               score += 7
    if any(t in d for t in SUSPICIOUS_TLDS): score += 9
    if u.count('-') > 2:               score += 5
    if len(url) > 100:                 score += 4
    if u.count('//') > 1:             score += 8
    matched = [kw for kw in PHISH_KEYWORDS if kw in u]
    score += min(len(matched) * 4, 16)
    return min(100, round(score))

def get_threat_level(score):
    if score <= 20:  return {'label':'Low',      'color':'#00e87a','bg':'rgba(0,232,122,.1)',  'border':'rgba(0,232,122,.25)'}
    if score <= 50:  return {'label':'Medium',   'color':'#ffd000','bg':'rgba(255,208,0,.1)',  'border':'rgba(255,208,0,.25)'}
    if score <= 75:  return {'label':'High',     'color':'#ff8f00','bg':'rgba(255,143,0,.1)',  'border':'rgba(255,143,0,.25)'}
    return              {'label':'Critical',  'color':'#ff3d5a','bg':'rgba(255,61,90,.1)',   'border':'rgba(255,61,90,.25)'}

def get_detailed_analysis(url):
    u = url.lower()
    d = get_domain(u)
    matched_kw = [kw for kw in PHISH_KEYWORDS if kw in u]
    has_ip = bool(re.search(r'\d{1,3}(\.\d{1,3}){3}', u))
    susp_tld = next((t for t in SUSPICIOUS_TLDS if t in d), None)
    return {
        'ssl': {
            'label': 'SSL / HTTPS',
            'status': 'safe' if 'https' in u else 'danger',
            'detail': 'Encrypted HTTPS connection detected' if 'https' in u else 'No encryption — plain HTTP only'
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
            'detail': f'Suspicious TLD detected: {susp_tld}' if susp_tld else 'Top-level domain appears normal'
        },
        'patterns': {
            'label': 'URL Patterns',
            'status': 'danger' if (has_ip or '@' in u or u.count('//') > 1) else 'safe',
            'detail': ' | '.join(filter(None, [
                'IP as domain' if has_ip else '',
                '@ symbol (redirect trick)' if '@' in u else '',
                'Multiple // (redirect)' if u.count('//') > 1 else '',
            ])) or 'No suspicious patterns'
        },
        'length': {
            'label': 'URL Length',
            'status': 'warning' if len(url) > 75 else 'safe',
            'detail': f'{len(url)} characters — {"suspicious length" if len(url) > 75 else "normal length"}'
        }
    }

def get_recommendations(result, analysis):
    recs = []
    if result == 'phishing':
        recs += ['Do NOT visit this URL under any circumstances',
                 'Report this URL to your organization\'s security team',
                 'If you already visited, change your passwords immediately',
                 'Run a malware scan on your device']
    if analysis['ssl']['status'] == 'danger':
        recs.append('Never enter credentials on HTTP-only sites')
    if analysis['keywords']['matches']:
        recs.append('Be suspicious of urgency-inducing language in URLs')
    if analysis['tld']['status'] == 'warning':
        recs.append('Exercise extreme caution with .xyz/.biz/.info domains')
    if result == 'safe':
        recs += ['Always verify the domain spelling carefully',
                 'Enable 2FA on important accounts for extra protection']
    return recs[:6]

# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/', methods=['GET', 'POST'])
def home():
    result = risk_score = threat = analysis = scan_id = url = None
    recommendations = []

    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        if url:
            feat    = extract_features(url)
            proba   = float(model.predict_proba([feat])[0][1])
            pred    = 1 if proba >= 0.5 else 0
            result  = 'phishing' if pred == 1 else 'safe'
            risk_score = compute_risk_score(url, feat, proba)
            threat  = get_threat_level(risk_score)
            analysis = get_detailed_analysis(url)
            recommendations = get_recommendations(result, analysis)
            scan_id = str(uuid.uuid4())[:8].upper()

            entry = {
                'id': scan_id, 'url': url, 'result': result,
                'risk_score': risk_score, 'threat_level': threat['label'],
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M'),
                'proba': round(proba * 100, 1)
            }
            scan_history.insert(0, entry)
            if len(scan_history) > 50:
                scan_history.pop()

    return render_template('index.html',
        url=url, result=result, risk_score=risk_score,
        threat=threat, analysis=analysis, scan_id=scan_id,
        recommendations=recommendations,
        recent=scan_history[:5])

@app.route('/dashboard')
def dashboard():
    total = len(scan_history)
    safe_count = sum(1 for s in scan_history if s['result'] == 'safe')
    phish_count = total - safe_count
    avg_risk = round(sum(s['risk_score'] for s in scan_history) / total, 1) if total else 0
    return render_template('dashboard.html',
        history=scan_history[:20], total=total,
        safe_count=safe_count, phish_count=phish_count, avg_risk=avg_risk)

@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({'error': "Missing 'url'"}), 400
    url  = data['url'].strip()
    feat = extract_features(url)
    proba = float(model.predict_proba([feat])[0][1])
    pred = 1 if proba >= 0.5 else 0
    result = 'phishing' if pred == 1 else 'safe'
    risk_score = compute_risk_score(url, feat, proba)
    threat = get_threat_level(risk_score)
    return jsonify({'url': url, 'result': result, 'risk_score': risk_score,
                    'threat_level': threat['label'], 'confidence': round(proba*100,1)})

@app.route('/api/stats')
def api_stats():
    total = len(scan_history)
    safe  = sum(1 for s in scan_history if s['result'] == 'safe')
    by_level = {'Low':0,'Medium':0,'High':0,'Critical':0}
    for s in scan_history:
        by_level[s['threat_level']] = by_level.get(s['threat_level'], 0) + 1
    return jsonify({'total': total, 'safe': safe, 'phishing': total-safe,
                    'avg_risk': round(sum(s['risk_score'] for s in scan_history)/total, 1) if total else 0,
                    'by_level': by_level, 'recent': scan_history[:10]})

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
        f"VERDICT:      {'⚠️  PHISHING DETECTED' if entry['result']=='phishing' else '✅  SAFE'}",
        f"RISK SCORE:   {entry['risk_score']}/100",
        f"THREAT LEVEL: {entry['threat_level']}",
        f"CONFIDENCE:   {entry['proba']}%",
        "=" * 60,
        "RECOMMENDATIONS:",
        "  • Never share credentials via links in emails/SMS",
        "  • Verify domain spelling before entering sensitive data",
        "  • Enable 2FA on all important accounts",
        "  • Report phishing to: report@phishing.gov.in",
        "=" * 60,
        "Generated by PhishGuard AI | For educational purposes",
    ]
    content = "\n".join(lines)
    return Response(content, mimetype='text/plain',
        headers={"Content-Disposition": f"attachment;filename=PhishGuard_Report_{scan_id}.txt"})

if __name__ == '__main__':
    app.run(debug=True)