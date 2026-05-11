import re

def extract_features(url):
    url = url.lower()
    domain = re.sub(r'https?://', '', url).split('/')[0]

    phishing_keywords = ['login', 'secure', 'bank', 'verify', 'update',
                         'account', 'confirm', 'password', 'free', 'prize',
                         'winner', 'claim', 'urgent', 'suspended', 'alert']

    return [
        len(url),                                               # 1. URL length
        url.count('.'),                                         # 2. number of dots
        int('https' in url),                                    # 3. https present
        int('@' in url),                                        # 4. @ symbol
        int('-' in domain),                                     # 5. dash in domain
        int(url.count('//') > 1),                               # 6. multiple //
        int(any(c.isdigit() for c in domain)),                  # 7. digits in domain
        sum(int(kw in url) for kw in phishing_keywords),        # 8. keyword count
        len(domain),                                            # 9. domain length
        int(url.startswith('http') == False),                   # 10. no http/https
        url.count('-'),                                         # 11. total dashes
        int(bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url))), # 12. IP address
        url.count('/'),                                         # 13. slash count
        int(domain.count('.') > 2),                            # 14. too many subdomains
        int(any(tld in domain for tld in ['.xyz', '.biz', '.info', '.net', '.club'])), # 15. suspicious TLD
    ]