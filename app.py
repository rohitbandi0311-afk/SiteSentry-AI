import ipaddress
import os
import socket
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request


load_dotenv(override=True)
app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False

SECURITY_HEADERS = {
    'Strict-Transport-Security': ('High', 'Enforces HTTPS for future visits.'),
    'Content-Security-Policy': ('High', 'Helps reduce cross-site scripting and content-injection risks.'),
    'X-Content-Type-Options': ('Medium', 'Prevents MIME-type sniffing.'),
    'X-Frame-Options': ('Medium', 'Helps prevent clickjacking.'),
    'Referrer-Policy': ('Low', 'Controls how much referrer information is shared.'),
    'Permissions-Policy': ('Low', 'Restricts access to browser features.'),
}


def validate_public_url(raw_url: str) -> str:
    parsed = urlparse(raw_url if '://' in raw_url else 'https://' + raw_url)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname:
        raise ValueError('Enter a valid http:// or https:// website URL.')
    if parsed.username or parsed.password:
        raise ValueError('URLs containing usernames or passwords are not accepted.')
    host = parsed.hostname
    if host.lower() in {'localhost', 'localhost.localdomain'}:
        raise ValueError('Localhost and private network targets are not allowed.')
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(host, None)}
    except socket.gaierror:
        raise ValueError('The hostname could not be resolved.')
    if not addresses:
        raise ValueError('The hostname did not resolve to an IP address.')
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            raise ValueError('Private, local, and non-public IP addresses are blocked.')
    return parsed.geturl()


def scan_site(url: str) -> dict:
    # A passive request only: no crawling, payloads, brute force, or exploitation.
    response = requests.get(
        url,
        timeout=10,
        allow_redirects=False,
        headers={'User-Agent': 'SiteSentryAI/0.1 (authorized passive security check)'},
        stream=True,
    )
    headers = response.headers
    findings = []
    for header, (severity, explanation) in SECURITY_HEADERS.items():
        if header.lower() not in {key.lower() for key in headers.keys()}:
            findings.append({
                'title': f'Missing {header}',
                'severity': severity,
                'evidence': f'The response did not include the {header} header.',
                'impact': explanation,
                'recommendation': f'Configure {header} with a policy appropriate for the application.'
            })
    if url.startswith('http://'):
        findings.append({
            'title': 'Website uses HTTP', 'severity': 'High',
            'evidence': 'The submitted URL uses the http:// scheme.',
            'impact': 'Traffic may be exposed or modified in transit.',
            'recommendation': 'Enable HTTPS with a valid TLS certificate and redirect HTTP to HTTPS.'
        })
    server_header = headers.get('Server')
    if server_header:
        findings.append({
            'title': 'Server header disclosed', 'severity': 'Low',
            'evidence': f'Server response header: {server_header[:120]}',
            'impact': 'Technology details may help an attacker fingerprint the server.',
            'recommendation': 'Consider minimizing version and product details in the Server header.'
        })
    status = response.status_code
    content_type = headers.get('Content-Type', 'Not provided')
    response.close()
    return {
        'url': url,
        'status_code': status,
        'content_type': content_type,
        'findings': findings,
        'checks_run': len(SECURITY_HEADERS) + 2,
        'note': 'Passive, unauthenticated checks only. This is not a full penetration test.'
    }



def gemma_explain(report: dict) -> str:
    api_key = os.getenv('GEMINI_API_KEY')

    if not api_key:
        return 'Gemma AI is not configured. Passive scan results are still available.'

    prompt = (
        'You are SiteSentry AI, a defensive website security assistant. '
        'Explain these passive scan findings for the site owner. '
        'Prioritize fixes and give safe configuration guidance. '
        'Do not claim missing headers prove exploitability. '
        'Clearly state scan limitations.\n\n'
        + str(report)
    )

    endpoint = (
        'https://generativelanguage.googleapis.com/v1beta/models/'
        'gemma-4-26b-a4b-it:generateContent'
    )

    try:
        response = requests.post(
            endpoint,
            params={'key': api_key},
            json={'contents': [{'parts': [{'text': prompt}]}]},
            timeout=(10, 60)
        )
        response.raise_for_status()
        data = response.json()
        candidate = data.get('candidates', [{}])[0]
        parts = candidate.get('content', {}).get('parts', [])
        text = ''.join(
            part.get('text', '')
            for part in parts
            if part.get('text')
        )
        return text or 'Gemma returned an empty response.'
    except requests.Timeout:
        return 'Gemma AI timed out. Passive scan results are still available.'

    
    except requests.RequestException as exc:
        status = getattr(exc.response, 'status_code', 'unknown')
        try:
            details = exc.response.json().get('error', {}).get('message', '')
        except (ValueError, AttributeError):
            details = ''
        return f'Gemma AI request failed (HTTP {status}): {details or type(exc).__name__}'

    except (ValueError, KeyError, IndexError, TypeError):
        return 'Gemma returned an unexpected response. Please try again.'



@app.get('/')
def home():
    return render_template('index.html')


@app.post('/api/scan')
def api_scan():
    payload = request.get_json(silent=True) or {}
    raw_url = str(payload.get('url', '')).strip()
    if not raw_url:
        return jsonify({'error': 'Enter a website URL.'}), 400
    try:
        safe_url = validate_public_url(raw_url)
        report = scan_site(safe_url)
        report['ai_explanation'] = gemma_explain(report)
        return jsonify(report)
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    except requests.RequestException as exc:
        return jsonify({'error': f'Could not fetch the website: {type(exc).__name__}'}), 502


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=int(os.getenv('PORT', '5000')), debug=True)
