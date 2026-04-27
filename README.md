# Vigilant-Vault: Zero-Trust Gateway for DPDP Compliance

Vigilant-Vault is a high-performance privacy middleware designed to help organizations comply with India's **Digital Personal Data Protection (DPDP) Act 2023**. It acts as a secure gateway that automatically detects, masks, and audits Personally Identifiable Information (PII) before it reaches your storage or analytics pipelines.

## 🚀 Live Demo
 [https://vigilant-vault.onrender.com](https://vigilant-vault.onrender.com)


## 🛡️ Core Features

### 1. Multi-Modal PII De-identification
- **Raw Text:** Instant masking of names, emails, phone numbers, and financial identifiers.
- **Document OCR:** Extracts and secures text from images (ID cards, receipts, documents) using Google Cloud Vision.
- **Batch CSV Processing:** Process entire datasets while maintaining schema integrity.

### 2. Zero-Trust Hashing & Auditing
Every processing request generates a cryptographic **Audit Certificate (JSON)**. 
- **Proof of Compliance:** Each certificate contains a SHA-256 hash that links the secured data to the specific processing event.
- **Integrity Verification:** Use the "Verify Audit" tab to prove that data has not been tampered with since it was secured.

### 3. DPDP Alignment
Specifically tuned to recognize Indian identifiers like **PAN Card numbers** and local contact formats, ensuring specialized protection for the Indian regulatory landscape.

## 🛠️ Technical Architecture

- **Backend:** Golang (High-concurrency processing)
- **Frontend:** React.js (Zero-Trust client-side verification)
- **APIs:** Google Cloud DLP (Data Loss Prevention) & Google Cloud Vision (OCR)
- **Security:** SHA-256 Cryptographic Hashing

## 📖 How to Use

1. **Secure Data:** Upload your CSV or paste text into the dashboard.
2. **Download Results:** Save your masked "Compliant" data and the accompanying "Audit Certificate."
3. **Verify:** Later, upload both files to the **Verify Audit** tab to confirm the digital signature matches, proving data integrity.
