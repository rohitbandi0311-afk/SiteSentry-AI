# SiteSentry AI

A Flask MVP for passive, defensive website security checks with Gemma 4 explanations.

## What it does
- Checks a small set of common HTTP security headers.
- Flags plain HTTP and a disclosed `Server` response header.
- Shows the response evidence and practical remediation suggestions.
- Uses Google's Gemma 4 through the Gemini API to explain findings when an API key is configured.

## Safety scope
Use only on websites you own or are explicitly authorized to assess. This MVP performs a single passive HTTP request, does not crawl, exploit, brute-force, or submit attack payloads, and blocks localhost/private/non-public IP targets. It is not a penetration test and cannot certify a site as secure. For a public production service, add stronger SSRF protections (DNS pinning/rebinding defenses, egress firewalling, rate limits, authentication, and a strict domain allowlist).

## Run on Windows
1. Install Python 3.10+.
2. Open this folder in PowerShell.
3. Create a virtual environment and install dependencies:

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```
4. Copy `.env.example` to `.env` and add your Google AI Studio API key as `GEMINI_API_KEY`.
5. Start the app:

   ```powershell
   py app.py
   ```
6. Open http://127.0.0.1:5000

Get a Gemini API key: https://aistudio.google.com/apikey

The app uses model ID `gemma-4-26b-a4b-it`. See Google's official Gemma API guide: https://ai.google.dev/gemma/docs/core/gemma_on_gemini_api
