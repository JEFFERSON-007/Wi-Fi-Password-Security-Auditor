# Wi-Fi Password Security Auditor

A professional, commercial-grade desktop application built in Python for evaluating and auditing the strength and security of Wi-Fi passwords. It is designed to assist system administrators, cybersecurity professionals, and home users in verifying that their wireless network keys are resilient against offline dictionary cracking and brute-force attacks.

> [!IMPORTANT]
> **Defensive & Educational Policy**
> This application is strictly a defensive self-auditing tool. It **never** attempts to capture handshakes, perform active brute-forcing over the air, bypass authentication, or connect to unauthorized wireless networks. It operates entirely locally in memory to evaluate user-entered keys.

---

## Features

- **Advanced Security Scoring**: Assesses passwords on a scale of 0 to 100 based on length, character set diversity, patterns, and entropy.
- **Deep Pattern Analysis**: Detects common keyboard patterns (e.g., `qwe`, `asdf`), sequential character runs (`abc`, `123`), repeated words, common/leaked passwords (matched against a built-in database of the 1,000 most common passwords), and personal identifier patterns (emails, phone numbers, and birth years).
- **Shannon Entropy Calculator**: Computes exact mathematical entropy bits (`L * log2(R)`) and character pool sizes to represent overall complexity.
- **Crack Time Estimator**: Provides estimated guess durations under different scenarios (Online Throttled, Desktop GPU Offline Cracking, and GPU Clusters).
- **Cryptographically Secure Generator**: Features standard character pool randomization (excluding ambiguous characters like `l`, `1`, `O`, `0`) and a NIST-compliant memorable multi-word passphrase mode using Python's `secrets` module.
- **Interactive Cyberpunk Dashboard**: Sleek dark-mode theme utilizing a custom animated canvas-drawn circular strength meter and dynamic checklist indicators.
- **Multi-Format Reporting Exporter**: Generates structured JSON data, plain text dashboards, or print-ready native PDF files without any external binary dependencies.

---

## Tech Stack & Architecture

- **Language**: Python 3.11+
- **GUI Engine**: Tkinter / TTK
- **Standard Library Modules**: `re`, `math`, `json`, `datetime`, `string`, `secrets`, `os`, `sys`
- **Dependencies**: 100% Standard Library. No external package installations are required.

### Project Directory Structure

```
WiFiPasswordAuditor/
├── main.py                 # Tkinter application UI and event control loop
├── analyzer.py             # Security score logic, pattern detection, entropy calculation
├── password_generator.py   # Cryptographically secure random password & passphrase generator
├── report.py               # Exporters for JSON, TXT, and custom binary-compliant PDF documents
├── common_passwords.json   # Base database of 1,000 leaked passwords
├── README.md               # User & architectural documentation
├── reports/                # Output directory for exported reports (auto-created)
└── assets/                 # Folder for styling references and images
```

---

## Installation

Since the project uses the Python standard library exclusively, installation is straightforward:

1. Clone or download this project workspace.
2. Ensure you have Python 3.11 or higher installed on your system.
3. Open a terminal/command prompt and navigate to the directory:
   ```bash
   cd WiFiPasswordAuditor
   ```
4. Run the application:
   ```bash
   python main.py
   ```

---

## Usage

### 1. Auditing a Password
1. Enter the password you want to test in the password input box.
2. Click **Show** or **Hide** to toggle the masking of characters.
3. Click the **Analyze Security** button.
4. Watch the circular gauge animate to show the score (0-100) and color rating.
5. Review the **Security Checklist** and **Recommendations** on the bottom pane to see how the password can be strengthened.

### 2. Exporting Reports
1. Run a password analysis.
2. The export buttons in the footer will activate.
3. Click **JSON Format**, **TXT Dashboard**, or **PDF Document**.
4. Choose where to save your file using the file selector. A copy will default to the `reports/` folder.

### 3. Generating Strong Credentials
1. Click the **Password Generator** tab in the sidebar.
2. Choose your mode:
   - **Random Password**: Choose character sets (Uppercase, Lowercase, Digits, Symbols), exclude ambiguous letters, and slide the bar to choose length (8-64).
   - **Memorable Passphrase**: Select the number of words (3-10), choosing a custom separator (e.g. `-`) and capitalization choice.
3. Click **Generate Secure Key**.
4. Click **Copy to Clipboard** to copy the value, or **Load into Security Auditor** to check the score of the newly generated key.

---

## Future Improvements

1. **Active WPA2 Key Check Integration**: Provide a secondary interface that checks local operating system profile database configs (via `netsh wlan show profile`) to audit already saved home networks.
2. **Local Password Database Expansion**: Allow users to load custom wordlists (e.g., RockYou) dynamically for offline comparison tests.
3. **Multi-language Localizations**: Add support for multiple language files for global security awareness programs.

---

## Git Repository Integration & Push Commands

To initialize this project as a Git repository and push it to GitHub, use the following sequence of terminal commands in your PowerShell or Command Prompt:

1. **Navigate to the Project Directory**:
   ```powershell
   cd "C:\Users\mariy\OneDrive\Documents\internship\codtech\2026\wifi password\WiFiPasswordAuditor"
   ```

2. **Initialize Git**:
   ```powershell
   git init
   ```

3. **Stage All Project Files**:
   ```powershell
   git add .
   ```

4. **Commit the Files**:
   ```powershell
   git commit -m "Initial commit: Wi-Fi Password Security Auditor"
   ```

5. **Set the Main Branch**:
   ```powershell
   git branch -M main
   ```

6. **Add the Remote Origin**:
   ```powershell
   git remote add origin https://github.com/JEFFERSON-007/Wi-Fi-Password-Security-Auditor.git
   ```

7. **Push to GitHub**:
   ```powershell
   git push -u origin main
   ```

---

## License

This project is licensed under the MIT License - see the LICENSE details for info.

