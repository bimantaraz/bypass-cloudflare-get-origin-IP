# bypass-cloudflare-get-origin-IP
A tool designed to help you bypass Cloudflare protection and find the origin IP of a protected domain. This tool uses various subdomain enumeration, DNS lookup, and MX check techniques to detect the origin IP address connecting to a server, even if the domain is protected by Cloudflare.

---

### Steps to Install and Run the Script

**1. Prepare the Python Environment:**
Make sure you have Python 3.6 or newer installed on your system.

* **Install Python 3.x**: You can download it from [python.org](https://www.python.org/downloads/).

**2. Clone the GitHub Repository or Download the Script:**

* If you want to download directly from GitHub, you can clone the repository using the command:

  ```bash
  git clone https://github.com/bimantaraz/bypass-cloudflare-get-origin-IP.git
  ```

**3. Install Dependencies:**
This tool requires several external libraries. You can install them using `pip` (Python package manager).

* Open a terminal or command prompt.
* Install the required libraries with the following command:

  ```bash
  pip install -r requirements.txt
  ```

**4. Running the Script:**
Once all dependencies are installed, you can run the script to start subdomain enumeration and find origin IPs behind Cloudflare.

* Open a terminal or command prompt.
* Navigate to the directory where the script file is saved.
* Run the following command:

  ```bash
  python teraz.py <domain>
  ```

  Replace `<domain>` with the domain name you want to analyze. For example:

  ```bash
  python teraz.py example.com
  ```

**5. Running with Custom Options:**
If you want to customize the list of subdomains or the type of DNS you want to query, you can add several optional arguments.

Some example commands with additional options:

* **Specify custom subdomains**:

  ```bash
  python teraz.py example.com --subdomains ftp mail api
  ```

* **Specify the DNS types to search for (A, MX, TXT, etc.)**:

  ```bash
  python teraz.py example.com --dns-types A MX
  ```

* **Use more threads to speed up the search**:

  ```bash
  python teraz.py example.com --max-workers 20
  ```

* **Save the results to a JSON file**:

  ```bash
  python teraz.py example.com --output results.json
  ```

**6. Viewing Results:**
This script will display the detected IPs in the terminal. You can also choose to save the results in JSON format for further analysis if you add the `--output` option.

---

### Key Features:

* **Subdomain Enumeration**: Enumerates common subdomains through DNS queries.
* **MX Record Checking**: Analyzes MX records to find IPs related to mail servers.
* **Cloudflare IP Check**: Avoids IPs associated with Cloudflare to discover unprotected origin IPs.
* **Formatted Output**: Results are printed with colors and organized tables for easy visualization.

### Example Output:

```
  ________________  ___ _____ 
 /_  __/ ____/ __ \/   /__  / 
  / / / __/ / /_/ / /| | / / 
 / / / /___/ _, _/ ___ |/ /__ 
/_/ /_____/_/ |_/_/  |_/____/ v1.0
         By github.com/bimantaraz

[INFO] Loaded 20 Cloudflare IP ranges.
--- Initiating Reconnaissance for example.com ---
[INFO] Loaded 20 Cloudflare IP ranges.
[PHASE 1] Commencing Subdomain Enumeration...
  [~] Testing mail.example.com -> 182.168.1.1
  [SUCCESS] Potential Origin IP Found: 182.168.1.1
  [~] Testing api.example.com -> 182.168.1.2
  [SUCCESS] Potential Origin IP Found: 182.168.1.2

[PHASE 2] Analyzing MX Records...
  [~] Found MX record: mail.example.com
  [SUCCESS] Potential Origin IP Found: 182.168.1.1

--- Reconnaissance Complete ---
Found the following potential origin IPs:
  -> 182.168.1.1
  -> 182.168.1.2
```
