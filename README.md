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
- **Multi-Factor Authentication (MFA) with TOTP**
- **Admin console for user management** (roles, status, force password reset, session timeout)
- **Session timeout** (admin configurable)
- **Profile management** (edit display name, phone, see account info)
- **Security settings page** (manage MFA)
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

5. **Database migrations:**
   - To add new columns/tables (e.g., for MFA, phone, settings), run migration scripts as needed:
     ```sh
     python3 migrate_force_password_reset.py
     python3 migrate_phone_column.py
     python3 migrate_setting_table.py
     ```

## Screenshots
![screenshot](screenshot.png)

## Customization & Extending
- Add more reputation sources by extending `ip_checker.py` and updating `app.py`.
- Tweak the UI in `templates/index.html` for your needs.
- Extend admin and profile features as desired.

## License
MIT
