import requests
import json
import sys
import ipaddress
import os
from dotenv import load_dotenv  # Add this import

# --- Configuration ---
# !! IMPORTANT: Replace placeholders with your actual keys !!
# !! BETTER: Load these from environment variables or a secure config file !!
# Example using environment variables:
# VT_API_KEY = os.getenv('VT_API_KEY')
# ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY')
# PULSEDIVE_API_KEY = os.getenv('PULSEDIVE_API_KEY')
# GREYNOISE_API_KEY = os.getenv('GREYNOISE_API_KEY')

# Load environment variables from .env file
load_dotenv()

# Fetch API keys from environment variables
VT_API_KEY = os.getenv('VT_API_KEY')
ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY')
PULSEDIVE_API_KEY = os.getenv('PULSEDIVE_API_KEY')
GREYNOISE_API_KEY = os.getenv('GREYNOISE_API_KEY')

# Check if keys are placeholder values and warn the user
if not VT_API_KEY or VT_API_KEY == "YOUR_VIRUSTOTAL_API_KEY" or \
   not ABUSEIPDB_API_KEY or ABUSEIPDB_API_KEY == "YOUR_ABUSEIPDB_API_KEY" or \
   not PULSEDIVE_API_KEY or PULSEDIVE_API_KEY == "YOUR_PULSEDIVE_API_KEY" or \
   not GREYNOISE_API_KEY or GREYNOISE_API_KEY == "YOUR_GREYNOISE_API_KEY":
    print("!!! WARNING: API keys are not set or are using placeholder values.")
    print("!!! Please edit the script or set environment variables (VT_API_KEY, ABUSEIPDB_API_KEY, PULSEDIVE_API_KEY, GREYNOISE_API_KEY).")
    # sys.exit("Exiting due to missing API keys.") # Optional: uncomment to exit if keys are missing

# --- Helper Functions ---

def is_valid_ip(ip_str):
    """Checks if the provided string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def get_virustotal_rep(ip, api_key):
    """Fetches IP reputation from VirusTotal API v3."""
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}
    report = {"source": "VirusTotal", "error": None, "data": None}

    try:
        response = requests.get(url, headers=headers, timeout=15) # Added timeout
        response.raise_for_status() # Raises HTTPError for bad responses (4XX, 5XX)

        data = response.json()
        # Extract relevant info - adjust as needed based on VT response structure
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        reputation = data.get("data", {}).get("attributes", {}).get("reputation", "N/A")
        as_owner = data.get("data", {}).get("attributes", {}).get("as_owner", "N/A")
        country = data.get("data", {}).get("attributes", {}).get("country", "N/A")

        report["data"] = {
            "Malicious": stats.get("malicious", 0),
            "Suspicious": stats.get("suspicious", 0),
            "Harmless": stats.get("harmless", 0),
            "Undetected": stats.get("undetected", 0),
            "Reputation Score": reputation,
            "AS Owner": as_owner,
            "Country": country,
            "Link": f"https://www.virustotal.com/gui/ip-address/{ip}/detection"
        }

    except requests.exceptions.Timeout:
        report["error"] = "Request timed out."
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            report["error"] = "IP address not found in VirusTotal."
        elif e.response.status_code == 401:
             report["error"] = "Authentication failed (Invalid API Key?)."
        else:
            report["error"] = f"HTTP Error: {e.response.status_code}"
    except requests.exceptions.RequestException as e:
        report["error"] = f"Request failed: {e}"
    except json.JSONDecodeError:
        report["error"] = "Failed to decode JSON response."
    except Exception as e:
        report["error"] = f"An unexpected error occurred: {e}"

    return report

def get_abuseipdb_rep(ip, api_key):
    """Fetches IP reputation from AbuseIPDB API v2."""
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        'Key': api_key,
        'Accept': 'application/json',
    }
    params = {
        'ipAddress': ip,
        'maxAgeInDays': '90', # Check reports within the last 90 days
        'verbose': '' # Add verbose flag for more details if needed
    }
    report = {"source": "AbuseIPDB", "error": None, "data": None}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=15)
        response.raise_for_status()

        data = response.json().get("data", {}) # API wraps result in "data" key
        if not data: # Handle cases where the IP might not be in the DB but doesn't return 4xx
             report["error"] = "IP address not found or no reports in AbuseIPDB."
             return report

        report["data"] = {
            "Abuse Confidence Score": data.get("abuseConfidenceScore", "N/A"),
            "Total Reports": data.get("totalReports", "N/A"),
            "Country": data.get("countryCode", "N/A"),
            "ISP": data.get("isp", "N/A"),
            "Domain": data.get("domain", "N/A"),
            "Usage Type": data.get("usageType", "N/A"),
            "Is Whitelisted": data.get("isWhitelisted", "N/A"),
            "Is TOR Node": data.get("isTor", "N/A"),
            "Last Reported At": data.get("lastReportedAt", "N/A"),
            "Link": f"https://www.abuseipdb.com/check/{ip}"
        }

    except requests.exceptions.Timeout:
        report["error"] = "Request timed out."
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 429:
            report["error"] = "API Rate Limit Exceeded."
        elif e.response.status_code == 401:
             report["error"] = "Authentication failed (Invalid API Key?)."
        elif e.response.status_code == 422: # Unprocessable Entity (e.g., invalid IP)
             report["error"] = f"Invalid Input or IP: {e.response.text}"
        else:
            report["error"] = f"HTTP Error: {e.response.status_code}"
    except requests.exceptions.RequestException as e:
        report["error"] = f"Request failed: {e}"
    except json.JSONDecodeError:
        report["error"] = "Failed to decode JSON response."
    except Exception as e:
        report["error"] = f"An unexpected error occurred: {e}"

    return report


def get_pulsedive_rep(ip, api_key):
    """Fetches IP reputation from Pulsedive API."""
    url = "https://pulsedive.com/api/info.php"
    params = {
        'indicator': ip,
        'key': api_key,
        'pretty': '1' # Makes the raw JSON response easier to read if debugging
    }
    report = {"source": "Pulsedive", "error": None, "data": None}

    try:
        response = requests.get(url, params=params, timeout=15)
        response.raise_for_status()

        data = response.json()
        if "error" in data: # Pulsedive often returns 200 OK with an error message in JSON
            report["error"] = data["error"]
            if "Indicator not found" in data["error"]:
                 report["error"] = "IP address not found in Pulsedive."
            return report

        # Extract relevant info - adjust based on Pulsedive response structure
        risk = data.get("risk", "N/A")
        risk_recommended = data.get("risk_recommended", "N/A")
        threats = [t.get("name", "N/A") for t in data.get("threats", [])]
        riskfactors = [rf.get("description", "N/A") for rf in data.get("riskfactors", [])]
        properties = data.get("properties", {})
        geo = properties.get("geo", {})

        report["data"] = {
            "Risk Level": risk,
            "Risk Recommended": risk_recommended,
            "Threats": ", ".join(threats) if threats else "None",
            "Risk Factors": ", ".join(riskfactors) if riskfactors else "None",
            "Country": geo.get("countrycode", "N/A"),
            "Technology": ", ".join(properties.get("technology", [])),
            "Link": f"https://pulsedive.com/indicator/{ip}"
        }

    except requests.exceptions.Timeout:
        report["error"] = "Request timed out."
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401: # Unauthorized
             report["error"] = "Authentication failed (Invalid API Key?)."
        elif e.response.status_code == 404: # Not Found (though sometimes they use 200 + error msg)
             report["error"] = "IP address not found in Pulsedive (API Error 404)."
        else:
            report["error"] = f"HTTP Error: {e.response.status_code}"
    except requests.exceptions.RequestException as e:
        report["error"] = f"Request failed: {e}"
    except json.JSONDecodeError:
        report["error"] = "Failed to decode JSON response."
    except Exception as e:
        report["error"] = f"An unexpected error occurred: {e}"

    return report


def get_greynoise_rep(ip, api_key):
    """Fetches IP reputation from GreyNoise API."""
    url = f"https://api.greynoise.io/v3/community/{ip}"
    headers = {"key": api_key, "Accept": "application/json"}
    report = {"source": "GreyNoise", "error": None, "data": None}
    try:
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        data = response.json()
        if data.get("message") == "IP address not observed":
            report["error"] = "IP address not observed by GreyNoise."
            return report
        report["data"] = {
            "Classification": data.get("classification", "N/A"),
            "Name": data.get("name", "N/A"),
            "Last Seen": data.get("last_seen", "N/A"),
            "Actor": data.get("actor", "N/A"),
            "Tags": ", ".join(data.get("tags", [])),
            "Link": f"https://viz.greynoise.io/ip/{ip}"
        }
    except requests.exceptions.Timeout:
        report["error"] = "Request timed out."
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            report["error"] = "IP address not found in GreyNoise."
        elif e.response.status_code == 401:
            report["error"] = "Authentication failed (Invalid API Key?)."
        else:
            report["error"] = f"HTTP Error: {e.response.status_code}"
    except requests.exceptions.RequestException as e:
        report["error"] = f"Request failed: {e}"
    except json.JSONDecodeError:
        report["error"] = "Failed to decode JSON response."
    except Exception as e:
        report["error"] = f"An unexpected error occurred: {e}"
    return report


def get_ip_info(ip):
    """Fetches IP information (ISP, location, etc.) using ipify and ip-api.com."""
    # We'll use ip-api.com for detailed info (ipify is best for public IP detection)
    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,zip,lat,lon,isp,org,as,query"
    info = {}
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        if data.get("status") != "success":
            info["error"] = data.get("message", "Failed to fetch IP info.")
        else:
            info = {
                "IP": data.get("query", "N/A"),
                "Country": data.get("country", "N/A"),
                "Region": data.get("regionName", "N/A"),
                "City": data.get("city", "N/A"),
                "ZIP": data.get("zip", "N/A"),
                "Latitude": data.get("lat", "N/A"),
                "Longitude": data.get("lon", "N/A"),
                "ISP": data.get("isp", "N/A"),
                "Organization": data.get("org", "N/A"),
                "AS": data.get("as", "N/A")
            }
    except Exception as e:
        info["error"] = f"Failed to fetch IP info: {e}"
    return info


def print_ip_info(ip_info):
    print("\n" + "-"*50)
    print(" IP Information:")
    print("-"*50)
    if "error" in ip_info:
        print(f"  Error: {ip_info['error']}")
    else:
        for key, value in ip_info.items():
            print(f"  {key}: {value}")
    print("\n" + "-"*50)


def print_report(ip, reports):
    """Formats and prints the reputation reports."""
    print("\n" + "="*50)
    print(f" IP Reputation Report for: {ip}")
    print("="*50)

    for report in reports:
        print(f"\n--- {report['source']} ---")
        if report["error"]:
            print(f"  Error: {report['error']}")
        elif report["data"]:
            for key, value in report["data"].items():
                print(f"  {key}: {value}")
        else:
            print("  No data received.")
    print("\n" + "="*50)

# --- Main Execution ---

if __name__ == "__main__":
    # Get IP address from command line argument or prompt user
    if len(sys.argv) > 1:
        ip_to_check = sys.argv[1]
        print(f"Checking IP from argument: {ip_to_check}")
    else:
        ip_to_check = input("Please enter the IP address to check: ")

    # Validate IP address
    if not is_valid_ip(ip_to_check):
        print(f"Error: '{ip_to_check}' is not a valid IP address.")
        sys.exit(1) # Exit with an error code

    # Fetch IP info
    ip_info = get_ip_info(ip_to_check)
    print_ip_info(ip_info)

    # Fetch reports (can be run in parallel using threading/asyncio for speed later)
    print(f"\nFetching reports for {ip_to_check}...")
    all_reports = []
    all_reports.append(get_virustotal_rep(ip_to_check, VT_API_KEY))
    all_reports.append(get_abuseipdb_rep(ip_to_check, ABUSEIPDB_API_KEY))
    all_reports.append(get_pulsedive_rep(ip_to_check, PULSEDIVE_API_KEY))
    all_reports.append(get_greynoise_rep(ip_to_check, GREYNOISE_API_KEY))

    # Print the consolidated report
    print_report(ip_to_check, all_reports)