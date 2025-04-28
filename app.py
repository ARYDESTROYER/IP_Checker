import os
from flask import Flask, render_template, request
from dotenv import load_dotenv
from ip_checker import (
    is_valid_ip,
    get_ip_info,
    get_virustotal_rep,
    get_abuseipdb_rep,
    get_pulsedive_rep,
    get_greynoise_rep
)

load_dotenv()

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    ip = ''
    ip_info = None
    reports = []
    error = None
    if request.method == 'POST':
        ip = request.form.get('ip', '').strip()
        if not is_valid_ip(ip):
            error = f"'{ip}' is not a valid IP address."
        else:
            ip_info = get_ip_info(ip)
            reports = [
                get_virustotal_rep(ip, os.getenv('VT_API_KEY')),
                get_abuseipdb_rep(ip, os.getenv('ABUSEIPDB_API_KEY')),
                get_pulsedive_rep(ip, os.getenv('PULSEDIVE_API_KEY')),
                get_greynoise_rep(ip, os.getenv('GREYNOISE_API_KEY')),
            ]
    return render_template('index.html', ip=ip, ip_info=ip_info, reports=reports, error=error)

if __name__ == '__main__':
    app.run(debug=True)
