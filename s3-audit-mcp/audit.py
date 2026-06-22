"""S3 audit checks: public bucket access, public-access-block gaps,
missing default encryption, and missing versioning.

Unlike EC2 instances, S3 buckets aren't tied to the client's configured
region -- `list_buckets` always returns every bucket in the account
regardless of region. To keep "audit <region>" meaning the same thing it
does for ec2-audit-mcp (only resources actually in that region), each
bucket's real region is resolved via `get_bucket_location` and filtered
against the requested region before any check runs.

Like EC2Auditor/IAMAuditor, this auditor never accepts AWS credentials as
input. It always uses boto3's default credential resolution, which inside
AWS means the Fargate task's IAM role -- the audited account's credentials
never leave the account boundary, and no caller (including the LLM) can
hand it different credentials than the ones it was deployed with.
"""

import boto3
from botocore.exceptions import ClientError
from typing import List, Dict, Any

PUBLIC_GROUP_URIS = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}

REQUIRED_PUBLIC_ACCESS_BLOCK_SETTINGS = [
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
]


class S3Auditor:
    def __init__(self, region: str):
        self.region = region
        self.client = boto3.client("s3", region_name=region)

    def audit(self) -> Dict[str, Any]:
        """Run full S3 audit and return findings."""
        findings = {
            "public_buckets": self._find_public_buckets(),
            "public_access_block_gaps": self._find_public_access_block_gaps(),
            "unencrypted_buckets": self._find_unencrypted_buckets(),
            "unversioned_buckets": self._find_unversioned_buckets(),
            "summary": {},
        }

        findings["summary"] = {
            "total_findings": sum(
                len(v) if isinstance(v, list) else 0
                for v in findings.values()
                if v != findings["summary"]
            ),
            "critical": self._count_severity(findings, "critical"),
            "high": self._count_severity(findings, "high"),
        }

        return findings

    def _buckets_in_region(self) -> List[str]:
        """List bucket names whose actual region matches the requested region."""
        response = self.client.list_buckets()
        return [
            bucket["Name"]
            for bucket in response["Buckets"]
            if self._bucket_region(bucket["Name"]) == self.region
        ]

    def _bucket_region(self, name: str) -> str:
        # LocationConstraint is None (not "us-east-1") for buckets created in
        # us-east-1 -- a long-standing S3 API quirk.
        response = self.client.get_bucket_location(Bucket=name)
        return response.get("LocationConstraint") or "us-east-1"

    def _find_public_buckets(self) -> List[Dict[str, Any]]:
        """Find buckets reachable via a public ACL grant or public bucket policy."""
        findings = []
        for name in self._buckets_in_region():
            if self._has_public_acl_grant(name) or self._has_public_policy(name):
                findings.append(
                    {
                        "bucket_name": name,
                        "severity": "critical",
                        "recommendation": "Remove public ACL grants and/or the public bucket policy immediately",
                    }
                )
        return findings

    def _has_public_acl_grant(self, name: str) -> bool:
        response = self.client.get_bucket_acl(Bucket=name)
        for grant in response.get("Grants", []):
            grantee = grant.get("Grantee", {})
            if grantee.get("Type") == "Group" and grantee.get("URI") in PUBLIC_GROUP_URIS:
                return True
        return False

    def _has_public_policy(self, name: str) -> bool:
        try:
            response = self.client.get_bucket_policy_status(Bucket=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
                return False
            raise
        return response.get("PolicyStatus", {}).get("IsPublic", False)

    def _find_public_access_block_gaps(self) -> List[Dict[str, Any]]:
        """Find buckets where S3 Block Public Access isn't fully enabled."""
        findings = []
        for name in self._buckets_in_region():
            config = self._public_access_block_config(name)
            missing = [s for s in REQUIRED_PUBLIC_ACCESS_BLOCK_SETTINGS if not config.get(s)]
            if missing:
                findings.append(
                    {
                        "bucket_name": name,
                        "missing_protections": missing,
                        "severity": "high",
                        "recommendation": "Enable all four S3 Block Public Access settings for this bucket",
                    }
                )
        return findings

    def _public_access_block_config(self, name: str) -> Dict[str, bool]:
        try:
            response = self.client.get_public_access_block(Bucket=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                return {}
            raise
        return response.get("PublicAccessBlockConfiguration", {})

    def _find_unencrypted_buckets(self) -> List[Dict[str, Any]]:
        """Find buckets with no default server-side encryption configured."""
        findings = []
        for name in self._buckets_in_region():
            if not self._has_default_encryption(name):
                findings.append(
                    {
                        "bucket_name": name,
                        "severity": "medium",
                        "recommendation": "Enable default server-side encryption (SSE-S3 or SSE-KMS) on this bucket",
                    }
                )
        return findings

    def _has_default_encryption(self, name: str) -> bool:
        try:
            response = self.client.get_bucket_encryption(Bucket=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
                return False
            raise
        rules = response.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
        return len(rules) > 0

    def _find_unversioned_buckets(self) -> List[Dict[str, Any]]:
        """Find buckets without versioning enabled."""
        findings = []
        for name in self._buckets_in_region():
            response = self.client.get_bucket_versioning(Bucket=name)
            if response.get("Status") != "Enabled":
                findings.append(
                    {
                        "bucket_name": name,
                        "severity": "medium",
                        "recommendation": "Enable versioning to protect against accidental deletion or overwrite",
                    }
                )
        return findings

    def _count_severity(self, findings: Dict, severity: str) -> int:
        """Count findings by severity."""
        count = 0
        for key, value in findings.items():
            if isinstance(value, list):
                count += sum(
                    1 for item in value if isinstance(item, dict) and item.get("severity") == severity
                )
        return count
