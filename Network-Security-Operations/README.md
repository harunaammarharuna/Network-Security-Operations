# Network Security Operations Labs – Wireshark PCAP Analysis

This repository contains two hands-on network security labs where I analyzed real-world **PCAP files** using **Wireshark** to investigate web application attacks, identify attackers, reconstruct attack chains, extract Indicators of Compromise (IOCs), and provide practical defensive recommendations.

These projects demonstrate core blue-team / SOC analyst skills:
- Deep packet inspection and traffic analysis
- Identifying exploitation techniques (SQL injection, unrestricted file upload → web shell)
- Reconstructing multi-stage attacks
- Geolocation of threat actors
- Documentation of IOCs and attack timelines
- Practical mitigation strategies for web application security

## Lab 1: SQL Injection → Database Breach → Admin Panel Compromise → Persistence

**Target scenario** — Compromise of an online bookstore web application (`bookworldstore.com`)

**Key findings:**
- **Attacker IP**: 111.224.250.131 (origin: China)
- **Initial vulnerability probed**: `/search.php` endpoint with classic SQL injection payloads (e.g. `book%27`)
- **First confirmed SQLi attempt**: `GET /search.php?search=book%27 HTTP/1.1`
- **Exfiltration technique**: UNION-based SQL injection using `SELECT` from `INFORMATION_SCHEMA` → full database mapping
- **Compromised database**: `bookworld_db` (contained sensitive user records)
- **Hidden admin directory discovered**: `/admin/index.php`
- **Compromised credentials**: `admin` / `admin123%21`
- **Persistence mechanism**: Uploaded malicious PHP backdoor → `NVri2vhp.php`

**Attack chain summary**:
1. Reconnaissance & vulnerability scanning  
2. Manual SQL injection probing → confirmation  
3. Database schema & data enumeration  
4. Credential harvesting → admin panel access  
5. Malicious file upload for long-term persistence

**Defensive recommendations** implemented in report:
- Prepared statements / parameterized queries
- Strong password policy + MFA
- Obscure / protect admin interfaces (VPN, IP whitelist, random path)
- Restrict executable file uploads in web directories

## Lab 2: Unrestricted File Upload → Web Shell → Command Execution → Data Exfiltration Attempt

**Target scenario** — Compromise of an e-commerce review upload feature (`shoporoma.com`)

**Key findings:**
- **Attacker IP**: 117.11.88.124 (city: Tianjin, China)
- **Attacker fingerprint**: `Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0` (Linux + Firefox)
- **Malicious web shell uploaded**: `image.jpg.php` (double extension bypass)
- **Upload directory**: `/reviews/uploads/`
- **Outbound C2 channel**: HTTP port 80
- **Exfiltration target**: `/etc/passwd` (via `cat /etc/passwd` + curl POST)

**Attack chain summary**:
1. Identification of unrestricted file upload vulnerability  
2. Upload of PHP web shell disguised as JPEG  
3. Command execution via web shell  
4. Attempted exfiltration of system user account information

**Defensive recommendations** implemented in report:
- Strict file-type validation (content inspection, not just extension)
- Store uploads in non-executable directories
- Automatic renaming of uploaded files to random strings
- Block unauthorized outbound connections from web servers

## Skills Demonstrated

- Advanced Wireshark usage (filters, statistics, HTTP/POST reconstruction, Follow → TCP Stream)
- IOC identification & documentation
- Geolocation via MaxMind
- Attack timeline reconstruction
- Understanding of common web vulnerabilities (OWASP Top 10: A03 Injection, A08 Software & Data Integrity Failures)
- Writing structured incident reports & mitigation advice

## Repository Contents

- `Network Security Operations Lab1.pdf` — Full report + Wireshark screenshots (Lab 1)
- `Network Security Operations Lab2.pdf` — Full report + Wireshark screenshots (Lab 2)
- Screenshots of key Wireshark findings (embedded in PDFs)

Feel free to review the reports for detailed packet-level evidence, payloads, and timelines.

## Tools Used

- Wireshark (packet analysis & reconstruction)
- MaxMind GeoIP (attribution)
- Standard Linux tools referenced in traffic (curl, cat)

---

🔒 These labs form part of my cybersecurity portfolio — showcasing practical network forensics and incident response capabilities.

Open to discussions, feedback, or collaboration on blue-team projects!