import os
import json
from datetime import datetime
from typing import Dict, Any, List

class AuditReporter:
    """
    Exports password analysis results to JSON, TXT, and PDF.
    Features a custom, dependency-free binary PDF generator.
    """
    @staticmethod
    def _pdf_escape(text: str) -> str:
        """Sanitizes text for standard PDF rendering with standard WinAnsiEncoding Helvetica."""
        # Strip non-ASCII characters or replace with ?
        cleaned = text.encode('ascii', errors='replace').decode('ascii')
        # Escape parenthesis and backslashes
        return cleaned.replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')

    @staticmethod
    def _mask_password(password: str) -> str:
        """Masks the password for safety in reports, leaving first and last visible if long."""
        if len(password) <= 4:
            return "*" * len(password)
        return password[0] + "*" * (len(password) - 2) + password[-1]

    @classmethod
    def export_to_json(cls, password: str, results: Dict[str, Any], filepath: str) -> str:
        """Exports the audit details in structured JSON format."""
        report_data = {
            "report_metadata": {
                "tool": "Wi-Fi Password Security Auditor",
                "timestamp": datetime.now().isoformat(),
                "notice": "This report evaluates password strength only. It does not perform active network penetration or authentication bypass."
            },
            "audit_data": {
                "masked_password": cls._mask_password(password),
                "length": len(password),
                "score": results["score"],
                "rating": results["rating"],
                "entropy_bits": results["entropy"],
                "pool_size": results["pool_size"],
                "combinations": str(results["combinations"]),
                "crack_time_estimates": results["crack_times"],
                "checklist": results["checklist"],
                "recommendations": results["recommendations"]
            }
        }
        
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=4)
        return filepath

    @classmethod
    def export_to_txt(cls, password: str, results: Dict[str, Any], filepath: str) -> str:
        """Exports the audit details in a clean, human-readable plain text dashboard format."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        masked = cls._mask_password(password)
        
        lines = [
            "=" * 60,
            "WI-FI PASSWORD SECURITY AUDIT REPORT",
            "=" * 60,
            f"Generated: {timestamp}",
            "Disclaimer: This report evaluates password strength only.",
            "            It does not perform active network penetration.",
            "-" * 60,
            f"Target Status:   AUDITED",
            f"Masked Key:      {masked}",
            f"Key Length:      {len(password)} characters",
            "-" * 60,
            f"Security Score:  {results['score']}/100",
            f"Overall Rating:  {results['rating'].upper()}",
            "-" * 60,
            "PASSWORD ENTROPY & METRICS",
            f"  - Entropy:            {results['entropy']} bits",
            f"  - Character Pool:     {results['pool_size']} characters",
            f"  - Est. Combinations:  {results['combinations']:.2e}",
            "-" * 60,
            "CRACK TIME ESTIMATES (Offline vs. Online)",
            f"  - Online Throttled (100 H/s):     {results['crack_times']['online']}",
            f"  - Desktop GPU (10 GH/s):          {results['crack_times']['offline_gpu']}",
            f"  - GPU Cluster (100 TH/s):         {results['crack_times']['gpu_cluster']}",
            "-" * 60,
            "SECURITY CHECKLIST",
        ]
        
        checklist_mapping = {
            "length": "Minimum 12 characters",
            "uppercase": "Contains uppercase letters",
            "lowercase": "Contains lowercase letters",
            "numbers": "Contains numbers",
            "symbols": "Contains symbols",
            "entropy": "High entropy (>60 bits)",
            "common": "Not a common/leaked password",
            "keyboard": "No keyboard patterns",
            "repeated": "No repeated characters"
        }
        
        for key, text in checklist_mapping.items():
            status = "[ PASS ]" if results["checklist"].get(key, False) else "[ FAIL ]"
            lines.append(f"  {status}  {text}")
            
        lines.append("-" * 60)
        lines.append("RECOMMENDATIONS")
        for rec in results["recommendations"]:
            lines.append(f"  * {rec}")
            
        lines.append("=" * 60)
        
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        return filepath

    @classmethod
    def export_to_pdf(cls, password: str, results: Dict[str, Any], filepath: str) -> str:
        """
        Exports the audit details in a high-fidelity, native PDF format
        generated directly from byte strings without external dependencies.
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        masked = cls._mask_password(password)
        
        # 1. Build the stream commands
        stream_parts = []
        
        # Draw background layout lines / borders
        stream_parts.append("1 w") # Line width
        stream_parts.append("0.1 0.15 0.25 RG") # Dark border color
        stream_parts.append("50 780 m 545 780 l S") # Top header line
        
        # Header title
        stream_parts.append("BT")
        stream_parts.append("/F2 18 Tf")
        stream_parts.append("50 795 Td")
        stream_parts.append(f"({cls._pdf_escape('WI-FI PASSWORD SECURITY AUDIT REPORT')}) Tj")
        stream_parts.append("ET")
        
        # Document Meta
        stream_parts.append("BT")
        stream_parts.append("/F1 10 Tf")
        stream_parts.append("14 TL")
        stream_parts.append("50 755 Td")
        stream_parts.append(f"(Generated: {cls._pdf_escape(timestamp)}) Tj T*")
        stream_parts.append(f"(Target: [User Wi-Fi Input]) Tj T*")
        stream_parts.append("ET")
        
        # Score Summary Card Background
        score = results["score"]
        rating = results["rating"]
        
        # Color coding score box
        if rating == "Excellent":
            rg_fill = "0.85 0.95 0.88 rg" # Emerald green
            rg_text = "0.05 0.45 0.2 rg"
        elif rating in ("Strong", "Good"):
            rg_fill = "0.88 0.93 0.98 rg" # Sky Blue
            rg_text = "0.08 0.35 0.55 rg"
        elif rating == "Fair":
            rg_fill = "1.0 0.95 0.82 rg" # Amber yellow
            rg_text = "0.6 0.4 0.0 rg"
        else:
            rg_fill = "1.0 0.88 0.88 rg" # Rose red
            rg_text = "0.65 0.1 0.1 rg"
            
        stream_parts.append(rg_fill)
        stream_parts.append("50 660 495 62 re f") # Filled rectangle
        
        # Score Text on box
        stream_parts.append("BT")
        stream_parts.append(rg_text)
        stream_parts.append("/F2 14 Tf")
        stream_parts.append("70 695 Td")
        stream_parts.append(f"(Security Score: {score}/100) Tj")
        stream_parts.append("0 -20 Td")
        stream_parts.append(f"(Audit Rating: {cls._pdf_escape(rating)}) Tj")
        stream_parts.append("ET")
        
        # Reset color
        stream_parts.append("0 0 0 rg")
        
        # Section 1: Password Metrics
        stream_parts.append("BT")
        stream_parts.append("/F2 12 Tf")
        stream_parts.append("50 630 Td")
        stream_parts.append("(PASSWORD ENTROPY & METRICS) Tj")
        stream_parts.append("ET")
        stream_parts.append("50 623 m 545 623 l S")
        
        # Left column metrics
        stream_parts.append("BT")
        stream_parts.append("/F1 10 Tf")
        stream_parts.append("14 TL")
        stream_parts.append("60 600 Td")
        stream_parts.append(f"(Masked Password: {cls._pdf_escape(masked)}) Tj T*")
        stream_parts.append(f"(Shannon Entropy: {results['entropy']} bits) Tj T*")
        stream_parts.append(f"(Est. Combinations: {results['combinations']:.3e}) Tj T*")
        stream_parts.append("ET")
        
        # Right column metrics
        stream_parts.append("BT")
        stream_parts.append("/F1 10 Tf")
        stream_parts.append("14 TL")
        stream_parts.append("320 600 Td")
        stream_parts.append(f"(Password Length: {len(password)} chars) Tj T*")
        stream_parts.append(f"(Character Pool Size: {results['pool_size']}) Tj T*")
        stream_parts.append(f"(Offline GPU Crack Time: {cls._pdf_escape(results['crack_times']['offline_gpu'])}) Tj T*")
        stream_parts.append("ET")
        
        # Section 2: Security Checklist
        stream_parts.append("BT")
        stream_parts.append("/F2 12 Tf")
        stream_parts.append("50 525 Td")
        stream_parts.append("(SECURITY AUDIT CHECKLIST) Tj")
        stream_parts.append("ET")
        stream_parts.append("50 518 m 545 518 l S")
        
        checklist_mapping = [
            ("length", "Minimum 12 characters"),
            ("uppercase", "Contains uppercase letters (A-Z)"),
            ("lowercase", "Contains lowercase letters (a-z)"),
            ("numbers", "Contains numeric characters (0-9)"),
            ("symbols", "Contains special symbols"),
            ("entropy", "High cryptographic entropy (>60 bits)"),
            ("common", "Not matched in common/leaked lists"),
            ("keyboard", "No simple keyboard sequential runs"),
            ("repeated", "No repeated character sequences")
        ]
        
        y = 495
        for key, text in checklist_mapping:
            passed = results["checklist"].get(key, False)
            status_text = "PASS" if passed else "FAIL"
            status_color = "0.05 0.45 0.2 rg" if passed else "0.65 0.1 0.1 rg"
            
            # Draw status box text
            stream_parts.append("BT")
            stream_parts.append(status_color)
            stream_parts.append("/F2 9 Tf")
            stream_parts.append(f"60 {y} Td")
            stream_parts.append(f"([{status_text}]) Tj")
            stream_parts.append("0 0 0 rg") # Reset text color
            
            # Draw item description
            stream_parts.append("/F1 9.5 Tf")
            stream_parts.append("40 0 Td")
            stream_parts.append(f"({cls._pdf_escape(text)}) Tj")
            stream_parts.append("ET")
            y -= 15
            
        # Section 3: Recommendations
        y_rec_sec = y - 10
        stream_parts.append("BT")
        stream_parts.append("/F2 12 Tf")
        stream_parts.append(f"50 {y_rec_sec} Td")
        stream_parts.append("(SECURITY RECOMMENDATIONS) Tj")
        stream_parts.append("ET")
        stream_parts.append(f"50 {y_rec_sec - 7} m 545 {y_rec_sec - 7} l S")
        
        y_rec = y_rec_sec - 22
        for rec in results["recommendations"]:
            stream_parts.append("BT")
            stream_parts.append("/F1 9.5 Tf")
            stream_parts.append(f"60 {y_rec} Td")
            stream_parts.append(f"(* {cls._pdf_escape(rec)}) Tj")
            stream_parts.append("ET")
            y_rec -= 15
            
        # Footer
        stream_parts.append("0.4 0.4 0.4 rg") # Grey footer
        stream_parts.append("BT")
        stream_parts.append("/F1 8 Tf")
        stream_parts.append("50 50 Td")
        stream_parts.append("(Disclaimer: This report evaluates password strength only. It does not perform active network attacks.) Tj")
        stream_parts.append("0 -12 Td")
        stream_parts.append("(Generated by Wi-Fi Password Security Auditor. For educational and defense purposes only.) Tj")
        stream_parts.append("ET")
        
        stream_content = "\n".join(stream_parts)
        stream_bytes = stream_content.encode('latin1')
        
        # 2. Build PDF objects structure
        obj_defs = {
            1: "<< /Type /Catalog /Pages 2 0 R >>",
            2: "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            3: "<< /Type /Page /Parent 2 0 R /Resources 4 0 R /MediaBox [0 0 595 842] /Contents 7 0 R >>",
            4: "<< /Font << /F1 5 0 R /F2 6 0 R >> >>",
            5: "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
            6: "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>"
        }
        
        # Output byte stream assembly
        output = bytearray()
        output.extend(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        
        offsets = {}
        
        # Write objects 1 to 6
        for idx in range(1, 7):
            offsets[idx] = len(output)
            obj_str = f"{idx} 0 obj\n{obj_defs[idx]}\nendobj\n"
            output.extend(obj_str.encode('latin1'))
            
        # Write object 7 (Contents stream)
        offsets[7] = len(output)
        stream_header = f"7 0 obj\n<< /Length {len(stream_bytes)} >>\nstream\n"
        output.extend(stream_header.encode('latin1'))
        output.extend(stream_bytes)
        output.extend(b"\nendstream\nendobj\n")
        
        # Write Cross-Reference (xref) table
        xref_offset = len(output)
        output.extend(b"xref\n0 8\n")
        output.extend(b"0000000000 65535 f \n")
        for idx in range(1, 8):
            offset_str = f"{offsets[idx]:010d} 00000 n \n"
            output.extend(offset_str.encode('latin1'))
            
        # Write Trailer
        trailer_str = (
            f"trailer\n<< /Size 8 /Root 1 0 R >>\n"
            f"startxref\n{xref_offset}\n%%EOF\n"
        )
        output.extend(trailer_str.encode('latin1'))
        
        # Write PDF to file
        with open(filepath, "wb") as f:
            f.write(output)
            
        return filepath
