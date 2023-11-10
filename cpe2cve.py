# Author: Matteo (xonoxitron) Pisani
# Description: Given a CPE, this script returns all related CVE, ordered by severity (desc)
# Usage: python3 cpe2cve.py -c cpe:2.3:a:apache:http_server:2.4.54

# Import necessary modules
import argparse
import requests


# Function to retrieve CVE data for a given CPE
def get_cve_data(cpe):
    base_url = "https://services.nvd.nist.gov/rest/json/cves/1.0"
    query_params = {"cpeName": cpe}
    response = requests.get(base_url, params=query_params)

    # Check if the request was successful (status code 200)
    if response.status_code == 200:
        cve_data = response.json()
        return cve_data.get("result", [])
    else:
        print(f"Error in HTTP request: {response.status_code}")
        return []


# Function to retrieve the CVE ID from a CVE object
def get_cve_id(cve):
    try:
        return cve["cve"]["CVE_data_meta"]["ID"]
    except (KeyError, TypeError, ValueError):
        # In case of missing or non-numeric data, assign a high value for non-evaluability
        return "N/A/"


# Function to retrieve metric version
def get_cve_metric_version(cve):
    if "baseMetricV4" in cve["impact"]:
        return "4"
    if "baseMetricV3" in cve["impact"]:
        return "3"
    if "baseMetricV2" in cve["impact"]:
        return "2"
    if "baseMetricV1" in cve["impact"]:
        return "1"
    return "N/A"


# Function to retrieve the score from a CVE object
def get_cve_score(cve):
    try:
        v = get_cve_metric_version(cve)
        return float(cve["impact"]["baseMetricV" + v]["cvssV" + v]["baseScore"])
    except (KeyError, TypeError, ValueError):
        # In case of missing or non-numeric data, assign a high value for non-evaluability
        return float("inf")


# Function to retrieve the severity from a CVE object
def get_cve_severity(cve):
    v = get_cve_metric_version(cve)
    cvss = cve["impact"]["baseMetricV" + v]
    if "severity" in cvss:
        return cvss["severity"]
    if "baseSeverity" in cvss["cvssV" + v]:
        return cvss["cvssV" + v]["baseSeverity"]
    return "N/A"


# Main function for parsing command-line arguments and performing the sorting and printing
def main():
    # Set up the argument parser
    parser = argparse.ArgumentParser(description="Get and sort CVEs from a CPE")
    parser.add_argument(
        "-c", "--cpe", required=True, help="CPE from which to retrieve CVEs"
    )
    args = parser.parse_args()

    # Retrieve CVE data for the given CPE
    cve_data = get_cve_data(args.cpe)

    # Sort the CVEs by score in descending order
    sorted_cve = sorted(cve_data["CVE_Items"], key=get_cve_score, reverse=True)

    # Print the sorted CVEs
    i = 1
    for cve in sorted_cve:
        cve_id = get_cve_id(cve)
        score = get_cve_score(cve)
        severity = get_cve_severity(cve)
        print(f"[{i}] ID: {cve_id}, Score: {score}, Severity: {severity}")
        i += 1


# Check if the script is being run directly
if __name__ == "__main__":
    main()
