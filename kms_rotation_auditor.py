### 2. `kms_rotation_auditor.py`
```python
#!/usr/bin/env python3
"""
AWS KMS Key Rotation & Usage Auditor
Scans Customer Managed Keys to enforce annual rotation status and identify stale keys.
"""

import boto3
import json
from datetime import datetime, timezone

def main():
    print("[+] Initializing AWS KMS Cryptographic Audit Engine...")
    kms_client = boto3.client('kms')
    audit_results = []
    
    # List all keys in the target account region
    try:
        keys = kms_client.list_keys(MaxItems=100)['Keys']
    except Exception as e:
        print(f"[-] Failed to query KMS API: {str(e)}")
        return

    for key in keys:
        key_id = key['KeyId']
        key_arn = key['KeyArn']
        
        # Describe Key to check origin and status (skip AWS managed keys)
        metadata = kms_client.describe_key(KeyId=key_id)['KeyMetadata']
        if metadata['KeyManager'] == 'AWS':
            continue
            
        print(f"[+] Evaluating Customer Managed Key: {key_id}")
        
        # 1. Audit Key Rotation Status
        rotation_status = False
        try:
            rotation_status = kms_client.get_key_rotation_status(KeyId=key_id)['KeyRotationEnabled']
        except kms_client.exceptions.UnsupportedOperationException:
            # Certain custom key stores or asymmetric keys don't support auto-rotation
            pass

        # 2. Key State Evaluation
        key_state = metadata['KeyState']
        creation_date = metadata['CreationDate'].replace(tzinfo=timezone.utc)
        days_old = (datetime.now(timezone.utc) - creation_date).days
        
        # Flag vulnerabilities
        violations = []
        if not rotation_status and metadata['KeySpec'] == 'SYMMETRIC_DEFAULT':
            violations.append("AUTOMATIC_ROTATION_DISABLED")
        if key_state != 'Enabled':
            violations.append(f"KEY_NOT_IN_ACTIVE_STATE:_{key_state.upper()}")

        if violations:
            audit_results.append({
                "KeyArn": key_arn,
                "KeySpec": metadata['KeySpec'],
                "DaysSinceCreation": days_old,
                "RotationEnabled": rotation_status,
                "ComplianceViolations": violations,
                "Status": "REMEDIATION_REQUIRED"
            })

    # Output absolute structural reporting
    compliance_payload = {
        "AuditTimestamp": datetime.now(timezone.utc).isoformat(),
        "TotalCustomerKeysAudited": len(audit_results),
        "NonCompliantKeys": audit_results
    }
    
    with open('kms_audit_report.json', 'w') as f:
        json.dump(compliance_payload, f, indent=4)
    print("[+] Cryptographic audit successfully finalized. Outputs saved to kms_audit_report.json")

if __name__ == '__main__':
    main()
