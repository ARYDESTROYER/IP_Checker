# IP Reputation Checker Web App

A simple web application to check the reputation and information of any IP address using multiple threat intelligence sources.

## Features
- Fetches detailed IP information (ISP, country, city, etc.)
- Reputation checks from:
  - VirusTotal
  - AbuseIPDB
  - Pulsedive
  - GreyNoise
- Highlights malicious and suspicious results
- Modern, responsive Bootstrap UI
- Easy setup with `.env` for API keys

## Setup

1. **Clone the repository** (if not already):
   ```sh
   git clone <your-repo-url>
   cd IP_Checker
   ```

2. **Install dependencies:**
   ```sh
   pip install -r requirements.txt
   ```

3. **Set your API keys:**
   - Copy `.env` template and fill in your keys:
     ```sh
     cp .env .env.local  # or just edit .env
     ```
   - Edit `.env` and add your API keys for VirusTotal, AbuseIPDB, Pulsedive, and GreyNoise.

4. **Run the web app:**
   ```sh
   python3 app.py
   ```
   Visit [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser.

## Screenshots
![screenshot](screenshot.png)

## Customization & Extending
- Add more reputation sources by extending `ip_checker.py` and updating `app.py`.
- Tweak the UI in `templates/index.html` for your needs.

## License
MIT
