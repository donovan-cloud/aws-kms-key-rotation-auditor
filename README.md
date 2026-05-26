# AWS KMS Key Rotation & Usage Auditor

[![Language](https://img.shields.io/badge/Language-Python%203.9%2B-blue.svg)](https://www.python.org/)
[![SDK](https://img.shields.io/badge/SDK-Boto3-orange.svg)](https://aws.amazon.com/pythonsdk/)
[![Compliance](https://img.shields.io/badge/Compliance-PCI--DSS%20%2F%20SOC%202-green.svg)](https://aws.amazon.com/kms/)

## 📋 Operational Overview

This repository houses a production-ready Python automation tool designed to audit **AWS Key Management Service (KMS)** configurations across an enterprise cloud estate. 

Cryptographic key management is a critical pillar of regulatory frameworks like PCI-DSS v4.0 and SOC 2 Type II. This tool programmatically scans all Customer Managed Keys (CMKs), verifies if automatic annual key rotation is enabled, checks for overly permissive key policies, and identifies stale keys that haven't been used to encrypt or decrypt data within the last 90 days.

---

### 🛡️ Core Security Capabilities

* **Rotation Enforcement Auditing:** Checks the `KeyRotationEnabled` boolean status across all active Customer Managed Keys to prevent compliance failures.
* **Stale Key Detection Engine:** Evaluates CloudTrail tracking or key state metadata to isolate cryptographic keys costing money without actively securing live data.
* **Key Policy Access Checks:** Flags structural key policies that allow dangerous root or wildcard principal administrative delegates.

---

## 📂 Repository Structural Mapping

```text
aws-kms-key-rotation-auditor/
├── README.md                      # Technical summary and security parameters
├── kms_rotation_auditor.py        # Core Python automation scanner
├── requirements.txt               # Script dependencies
└── kms_audit_report.json          # Live mock verification output ledger
