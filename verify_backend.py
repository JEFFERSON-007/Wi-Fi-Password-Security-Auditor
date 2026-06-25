import os
import json
from datetime import datetime
from analyzer import PasswordAnalyzer
from password_generator import PasswordGenerator
from report import AuditReporter

def test_wifi_auditor():
    print("==================================================")
    print("RUNNING WI-FI PASSWORD SECURITY AUDITOR TESTS")
    print("==================================================")

    # 1. Initialize Modules
    print("[1/5] Initializing modules...")
    analyzer = PasswordAnalyzer()
    generator = PasswordGenerator()
    print("  - Modules successfully initialized.")

    # 2. Test Weak Password Analysis
    print("\n[2/5] Testing analysis on weak password ('123456')...")
    weak_res = analyzer.analyze("123456")
    print(f"  - Score: {weak_res['score']}/100")
    print(f"  - Rating: {weak_res['rating']}")
    print(f"  - Entropy: {weak_res['entropy']} bits")
    print(f"  - Is Not Common Checklist: {weak_res['checklist']['common']}")
    
    assert weak_res['score'] <= 10, "Weak password score should be extremely low!"
    assert weak_res['checklist']['common'] is False, "123456 should be flagged as a common password!"
    print("  - Weak password checks passed.")

    # 3. Test Strong Password Analysis
    print("\n[3/5] Testing analysis on strong password ('C0mplex_P@ssw0rd_2026')...")
    strong_res = analyzer.analyze("C0mplex_P@ssw0rd_2026")
    print(f"  - Score: {strong_res['score']}/100")
    print(f"  - Rating: {strong_res['rating']}")
    print(f"  - Entropy: {strong_res['entropy']} bits")
    print(f"  - Checklist status: All ticks: {all(strong_res['checklist'].values())}")
    
    assert strong_res['score'] >= 80, "Complex password score should be high!"
    print("  - Strong password checks passed.")

    # 4. Test Generator
    print("\n[4/5] Testing cryptographically secure generator...")
    # Standard password
    std_pwd = generator.generate_secure_password(length=18, use_symbols=True)
    print(f"  - Generated Standard (18 chars): {std_pwd}")
    assert len(std_pwd) == 18, "Standard generator length should match 18!"
    
    # Passphrase
    phrase = generator.generate_passphrase(words_count=5, separator="-")
    print(f"  - Generated Passphrase (5 words): {phrase}")
    assert len(phrase.split("-")) == 5, "Passphrase word count should match 5!"
    print("  - Generator checks passed.")

    # 5. Test Exporter
    print("\n[5/5] Testing report exporters (JSON, TXT, PDF)...")
    reports_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
    os.makedirs(reports_dir, exist_ok=True)
    
    json_path = os.path.join(reports_dir, "test_report.json")
    txt_path = os.path.join(reports_dir, "test_report.txt")
    pdf_path = os.path.join(reports_dir, "test_report.pdf")
    
    # Export reports
    AuditReporter.export_to_json("C0mplex_P@ssw0rd_2026", strong_res, json_path)
    AuditReporter.export_to_txt("C0mplex_P@ssw0rd_2026", strong_res, txt_path)
    
    # Build data for PDF
    pdf_data = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "score": strong_res["score"],
        "rating": strong_res["rating"],
        "entropy": strong_res["entropy"],
        "pool_size": strong_res["pool_size"],
        "combinations_str": f"{strong_res['combinations']:.2e}",
        "masked_password": AuditReporter._mask_password("C0mplex_P@ssw0rd_2026"),
        "length": len("C0mplex_P@ssw0rd_2026"),
        "crack_times": strong_res["crack_times"],
        "checklist_items": [
            ("Minimum 12 characters", strong_res["checklist"].get("length", False)),
            ("Contains uppercase letters (A-Z)", strong_res["checklist"].get("uppercase", False)),
            ("Contains lowercase letters (a-z)", strong_res["checklist"].get("lowercase", False)),
            ("Contains numeric characters (0-9)", strong_res["checklist"].get("numbers", False)),
            ("Contains special symbols", strong_res["checklist"].get("symbols", False)),
            ("High cryptographic entropy (>60 bits)", strong_res["checklist"].get("entropy", False)),
            ("Not matched in common/leaked lists", strong_res["checklist"].get("common", False)),
            ("No simple keyboard sequential runs", strong_res["checklist"].get("keyboard", False)),
            ("No repeated character strings", strong_res["checklist"].get("repeated", False))
        ],
        "recommendations": strong_res["recommendations"]
    }
    AuditReporter.export_to_pdf("C0mplex_P@ssw0rd_2026", pdf_data, pdf_path)
    
    # Assertions
    assert os.path.exists(json_path), "JSON report should be generated!"
    assert os.path.exists(txt_path), "TXT report should be generated!"
    assert os.path.exists(pdf_path), "PDF report should be generated!"
    
    print(f"  - Files written to: {reports_dir}")
    print("  - Exporter checks passed.")
    
    print("\n==================================================")
    print("SUCCESS: ALL WI-FI SECURITY AUDITOR TESTS PASSED!")
    print("==================================================")

if __name__ == "__main__":
    test_wifi_auditor()
