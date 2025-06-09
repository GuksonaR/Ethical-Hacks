Ethical Hacks — Full Explanation of All 25 Scripts
Reminder: These tools are for education and testing only on networks or devices you own or have permission to test.

1. DNS Spoofing (/dns_spoof.txt)
What it does:
Intercepts DNS requests and tricks the requester by sending back fake IP addresses for certain domains (like “example.com”).

How it works:

Listens to network packets for DNS queries.

When it detects a query for “example.com,” it replies with a fake IP address.

Uses the Python library Scapy for packet sniffing and crafting fake responses.

Why antivirus flags it:
Because it manipulates network traffic, a common behavior in malware or attacks.

2. Email Spoofing (/email_spoof.txt)
What it does:
Sends emails that look like they come from someone else (fake sender address).

How it works:

Uses Python’s smtplib to connect to an SMTP email server.

Crafts an email with a forged “From” address.

Sends it to a target email.

Why antivirus flags it:
Sending fake emails is a common phishing technique, so antivirus flags this behavior.

3. File Upload Checker (/file_upload_checker.txt)
What it does:
Uploads a file to a website URL to check if the site accepts file uploads.

How it works:

Takes a URL input.

Uses Python’s requests library to send a POST request with a file attached.

Checks the server’s response.

Why antivirus flags it:
Automated file upload tools can be used for malicious uploads, like malware.

4. FTP Anonymous Login Check (/ftp_anonymous_login_check.txt)
What it does:
Tests if an FTP server allows anonymous login (no username or password).

How it works:

Attempts to connect to FTP servers without credentials.

Checks if login succeeds.

Why antivirus flags it:
Trying to access servers anonymously is suspicious behavior.

5. HTTP Header Grabber (/http_header_grabber.txt)
What it does:
Retrieves HTTP headers from a website.

How it works:

Opens a socket connection to a website.

Sends an HTTP HEAD request.

Reads response headers.

Why antivirus flags it:
Network scanning tools can be suspicious if used without permission.

6. IP Geolocation API (/ip_geolocation_api.txt)
What it does:
Gets the location info (country, city) of an IP address using online APIs.

How it works:

Sends a request to a public IP geolocation service.

Parses and shows results.

Why antivirus flags it:
Generally safe, but API abuse or suspicious queries might raise flags.

7. Keylogger (/keylogger.txt)
What it does:
Records all keyboard input on a computer.

How it works:

Uses Python’s pynput library to listen for keyboard events.

Saves keystrokes to a file.

Why antivirus flags it:
Keyloggers are dangerous malware, so antivirus blocks them immediately.

8. Password Generator (/password_generator.txt)
What it does:
Generates strong random passwords.

How it works:

Uses Python’s random and string libraries.

Combines letters, numbers, and symbols to create passwords.

Why antivirus flags it:
This one is safe, usually not flagged.

9. Password Hash Cracker (/password_hash_cracker.txt)
What it does:
Tries to guess the original password from an MD5 hash using a wordlist.

How it works:

Takes an MD5 hash.

Compares it against hashes of common passwords from a list.

If a match is found, shows the original password.

Why antivirus flags it:
Used for cracking passwords, which is sensitive behavior.

10. Port Scanner (/port_scanner.txt)
What it does:
Checks which network ports are open on a target IP.

How it works:

Attempts to connect to a list of ports on a target.

Reports which ports respond.

Why antivirus flags it:
Port scanning is often used by attackers to find vulnerabilities.

11. Simple HTTP Server (/simple_http_server.txt)
What it does:
Starts a basic web server to serve files from a folder.

How it works:

Uses Python’s built-in http.server module.

Opens a port and shares files over the network.

Why antivirus flags it:
Running a server may look suspicious on some setups.

12. SQL Injection Test (/simple_sql_injection_test.txt)
What it does:
Tests a website for SQL injection flaws.

How it works:

Sends URLs with malicious SQL payloads.

Checks if server responses reveal database errors or vulnerabilities.

Why antivirus flags it:
SQL injection testing mimics hacking attacks.

13. UDP Flood (/simple_udp_flood.txt)
What it does:
Sends a flood of UDP packets to a target to overwhelm it.

How it works:

Continuously sends UDP packets with random data to an IP and port.

Why antivirus flags it:
Used in denial-of-service (DoS) attacks, very dangerous and illegal without permission.

14. XSS Scanner (/simple_xss_scanner.txt)
What it does:
Checks if a website is vulnerable to cross-site scripting (XSS).

How it works:

Sends payloads in URL parameters.

Looks if payloads get reflected in the page without sanitization.

Why antivirus flags it:
XSS scanning mimics hacking attempts.

15. HTTP Packet Sniffer (/sniff_http_packets.txt)
What it does:
Captures and shows HTTP network packets.

How it works:

Uses Scapy to capture packets.

Filters and prints HTTP data.

Why antivirus flags it:
Packet sniffing is used by attackers to spy on networks.

16. SSH Brute Force (/ssh_bruteforce.txt)
What it does:
Tries many passwords to log into an SSH server.

How it works:

Uses paramiko library to attempt SSH logins repeatedly with different passwords.

Why antivirus flags it:
Brute force attacks are illegal without permission and flagged as hacking.

17. Subdomain Scanner (/subdomain_scanner.txt)
What it does:
Checks if subdomains exist for a given domain.

How it works:

Sends requests to common subdomains (like admin.domain.com).

Reports which ones respond.

Why antivirus flags it:
Reconnaissance activity, often used before attacks.

18. SYN Scan (/syn_scan.txt)
What it does:
Performs a stealthy scan to see which ports respond to TCP SYN packets.

How it works:

Uses Scapy to send SYN packets.

Analyzes responses to determine if ports are open.

Why antivirus flags it:
Stealth scanning is used by attackers.

19. WHOIS Lookup (/whois_lookup.txt)
What it does:
Retrieves registration info of a domain or IP.

How it works:

Connects to WHOIS servers.

Downloads ownership and contact data.

Why antivirus flags it:
Usually safe, but bulk WHOIS queries might raise flags.

20. WiFi Password Grabber (Windows) (/wifi_password_grabber_windows.txt)
What it does:
Shows saved WiFi passwords on a Windows PC.

How it works:

Runs Windows commands via subprocess.

Extracts stored WiFi network keys.

Why antivirus flags it:
Revealing passwords is sensitive and risky.

21. ARP Scanner (/arp_scanner.txt)
What it does:
Finds active devices on a local network by sending ARP requests.

How it works:

Uses Scapy to send ARP requests.

Lists devices that respond.

Why antivirus flags it:
Network scanning can be suspicious.

22. ARP Spoofing (/arp_spoof.txt)
What it does:
Redirects network traffic by sending fake ARP messages.

How it works:

Sends forged ARP replies to trick devices into sending traffic to you.

Why antivirus flags it:
Used in man-in-the-middle attacks; illegal without permission.

23. Banner Grabber (/banner_grabber.txt)
What it does:
Connects to a network service and grabs the banner (info about software/version).

How it works:

Opens a connection to a port.

Reads the initial response banner.

Why antivirus flags it:
Information gathering tool used in reconnaissance.

24. Directory Bruteforce (/directory_bruteforce.txt)
What it does:
Checks if common folders exist on a web server.

How it works:

Sends GET requests for popular directory names.

Reports which return a successful response.

Why antivirus flags it:
Used to find hidden files/folders before attacks.

--------------------------------------------------

Final tip:
Always use a virtual machine (VM) or isolated test environment when running these scripts. Never run them on your main system without proper safeguards.
