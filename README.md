# cpe2cve 🔍🛡️

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Overview

This a Python script that retrieves and organizes Common Vulnerabilities and Exposures (CVE) data related to a given Common Platform Enumeration (CPE). The script uses the National Vulnerability Database (NVD) API to fetch relevant information and presents it in a sorted order based on severity.

## Usage

### Prerequisites

- Python 3.x
- Requests library (install using `pip install requests`)

### Example

```bash
python3 cpe2cve.py -c cpe:2.3:a:apache:http_server:2.4.54
```

Replace the example CPE with your specific CPE for analysis.

## Features

- Fetches CVE data for a given CPE.
- Sorts CVEs by severity in descending order.
- Displays CVE details, including ID, score, and severity.

## Sample Output

```bash
[1] ID: CVE-2023-25690, Score: 9.8, Severity: CRITICAL
[2] ID: CVE-2022-36760, Score: 9.0, Severity: CRITICAL
[3] ID: CVE-2023-31122, Score: 7.5, Severity: HIGH
[4] ID: CVE-2013-4365, Score: 7.5, Severity: HIGH
[5] ID: CVE-2023-27522, Score: 7.5, Severity: HIGH
[6] ID: CVE-2006-20001, Score: 7.5, Severity: HIGH
[7] ID: CVE-2007-4723, Score: 7.5, Severity: HIGH
[8] ID: CVE-2011-2688, Score: 7.5, Severity: HIGH
[9] ID: CVE-2023-45802, Score: 5.9, Severity: MEDIUM
[10] ID: CVE-2022-37436, Score: 5.3, Severity: MEDIUM
[11] ID: CVE-2013-2765, Score: 5.0, Severity: MEDIUM
[12] ID: CVE-2009-2299, Score: 5.0, Severity: MEDIUM
[13] ID: CVE-2012-4001, Score: 5.0, Severity: MEDIUM
[14] ID: CVE-2012-3526, Score: 5.0, Severity: MEDIUM
[15] ID: CVE-2011-1176, Score: 4.3, Severity: MEDIUM
[16] ID: CVE-2012-4360, Score: 4.3, Severity: MEDIUM
[17] ID: CVE-2013-0942, Score: 4.3, Severity: MEDIUM
[18] ID: CVE-2009-0796, Score: 2.6, Severity: LOW
[19] ID: CVE-2013-0941, Score: 2.1, Severity: LOW
```

## Contributing

If you find any issues or have suggestions for improvements, please open an issue or create a pull request. Contributions are welcome!

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.