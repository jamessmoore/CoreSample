import pytest
from unittest.mock import MagicMock, patch
from audit import EC2Auditor

TAGGED_INSTANCE = {
    "InstanceId": "i-tagged",
    "Tags": [
        {"Key": "Name", "Value": "web-01"},
        {"Key": "Environment", "Value": "prod"},
        {"Key": "Owner", "Value": "james"},
    ],
}

UNTAGGED_INSTANCE = {"InstanceId": "i-untagged"}

PUBLIC_INSTANCE = {
    "InstanceId": "i-public",
    "PublicIpAddress": "54.1.2.3",
    "Tags": TAGGED_INSTANCE["Tags"],
}

PRIVATE_INSTANCE = {
    "InstanceId": "i-private",
    "Tags": TAGGED_INSTANCE["Tags"],
}


def make_auditor(mock_client: MagicMock) -> EC2Auditor:
    with patch("audit.boto3.client", return_value=mock_client):
        return EC2Auditor(region="us-east-1")


def reservations(*instances):
    return {"Reservations": [{"Instances": list(instances)}]}


def sg(group_id, group_name, from_port, cidr="0.0.0.0/0"):
    return {
        "GroupId": group_id,
        "GroupName": group_name,
        "IpPermissions": [
            {
                "FromPort": from_port,
                "ToPort": from_port,
                "IpProtocol": "tcp",
                "IpRanges": [{"CidrIp": cidr}],
            }
        ],
    }


# ---------------------------------------------------------------------------
# _find_untagged
# ---------------------------------------------------------------------------

class TestFindUntagged:
    def test_fully_tagged_instance_not_reported(self):
        mock_client = MagicMock()
        mock_client.describe_instances.return_value = reservations(TAGGED_INSTANCE)
        assert make_auditor(mock_client)._find_untagged() == []

    def test_instance_with_no_tags_is_reported(self):
        mock_client = MagicMock()
        mock_client.describe_instances.return_value = reservations(UNTAGGED_INSTANCE)
        result = make_auditor(mock_client)._find_untagged()
        assert len(result) == 1
        finding = result[0]
        assert finding["instance_id"] == "i-untagged"
        assert set(finding["missing_tags"]) == {"Name", "Environment", "Owner"}
        assert finding["severity"] == "high"
        assert "recommendation" in finding

    def test_partial_tags_reports_only_missing_keys(self):
        instance = {
            "InstanceId": "i-partial",
            "Tags": [{"Key": "Name", "Value": "db-01"}],
        }
        mock_client = MagicMock()
        mock_client.describe_instances.return_value = reservations(instance)
        result = make_auditor(mock_client)._find_untagged()
        assert len(result) == 1
        assert set(result[0]["missing_tags"]) == {"Environment", "Owner"}

    def test_multiple_instances_across_reservations(self):
        mock_client = MagicMock()
        mock_client.describe_instances.return_value = {
            "Reservations": [
                {"Instances": [UNTAGGED_INSTANCE]},
                {"Instances": [TAGGED_INSTANCE]},
                {"Instances": [{"InstanceId": "i-also-untagged"}]},
            ]
        }
        result = make_auditor(mock_client)._find_untagged()
        ids = {r["instance_id"] for r in result}
        assert ids == {"i-untagged", "i-also-untagged"}

    def test_empty_reservations_returns_empty_list(self):
        mock_client = MagicMock()
        mock_client.describe_instances.return_value = {"Reservations": []}
        assert make_auditor(mock_client)._find_untagged() == []

    def test_correct_filter_sent_to_boto3(self):
        mock_client = MagicMock()
        mock_client.describe_instances.return_value = {"Reservations": []}
        make_auditor(mock_client)._find_untagged()
        mock_client.describe_instances.assert_called_once_with(
            Filters=[{"Name": "instance-state-name", "Values": ["running", "stopped"]}]
        )


# ---------------------------------------------------------------------------
# _find_public_ips
# ---------------------------------------------------------------------------

class TestFindPublicIps:
    def test_instance_with_public_ip_is_reported(self):
        mock_client = MagicMock()
        mock_client.describe_instances.return_value = reservations(PUBLIC_INSTANCE)
        result = make_auditor(mock_client)._find_public_ips()
        assert len(result) == 1
        finding = result[0]
        assert finding["instance_id"] == "i-public"
        assert finding["public_ip"] == "54.1.2.3"
        assert finding["severity"] == "medium"
        assert "recommendation" in finding

    def test_instance_without_public_ip_not_reported(self):
        mock_client = MagicMock()
        mock_client.describe_instances.return_value = reservations(PRIVATE_INSTANCE)
        assert make_auditor(mock_client)._find_public_ips() == []

    def test_mixed_instances_only_public_reported(self):
        mock_client = MagicMock()
        mock_client.describe_instances.return_value = reservations(PUBLIC_INSTANCE, PRIVATE_INSTANCE)
        result = make_auditor(mock_client)._find_public_ips()
        assert len(result) == 1
        assert result[0]["instance_id"] == "i-public"

    def test_empty_reservations_returns_empty_list(self):
        mock_client = MagicMock()
        mock_client.describe_instances.return_value = {"Reservations": []}
        assert make_auditor(mock_client)._find_public_ips() == []

    def test_correct_filter_sent_to_boto3(self):
        mock_client = MagicMock()
        mock_client.describe_instances.return_value = {"Reservations": []}
        make_auditor(mock_client)._find_public_ips()
        mock_client.describe_instances.assert_called_once_with(
            Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
        )


# ---------------------------------------------------------------------------
# _audit_security_groups
# ---------------------------------------------------------------------------

class TestAuditSecurityGroups:
    def test_ssh_world_open_is_critical(self):
        mock_client = MagicMock()
        mock_client.describe_security_groups.return_value = {
            "SecurityGroups": [sg("sg-001", "open-ssh", 22)]
        }
        result = make_auditor(mock_client)._audit_security_groups()
        assert len(result) == 1
        assert result[0]["severity"] == "critical"
        assert result[0]["security_group_id"] == "sg-001"

    def test_rdp_world_open_is_critical(self):
        mock_client = MagicMock()
        mock_client.describe_security_groups.return_value = {
            "SecurityGroups": [sg("sg-002", "open-rdp", 3389)]
        }
        result = make_auditor(mock_client)._audit_security_groups()
        assert result[0]["severity"] == "critical"

    def test_other_port_world_open_is_high(self):
        mock_client = MagicMock()
        mock_client.describe_security_groups.return_value = {
            "SecurityGroups": [sg("sg-003", "open-http", 80)]
        }
        result = make_auditor(mock_client)._audit_security_groups()
        assert len(result) == 1
        assert result[0]["severity"] == "high"

    def test_restricted_cidr_not_reported(self):
        mock_client = MagicMock()
        mock_client.describe_security_groups.return_value = {
            "SecurityGroups": [sg("sg-004", "restricted", 22, cidr="10.0.0.0/8")]
        }
        assert make_auditor(mock_client)._audit_security_groups() == []

    def test_sg_with_no_ip_permissions_not_reported(self):
        mock_client = MagicMock()
        mock_client.describe_security_groups.return_value = {
            "SecurityGroups": [{"GroupId": "sg-005", "GroupName": "empty", "IpPermissions": []}]
        }
        assert make_auditor(mock_client)._audit_security_groups() == []

    def test_multiple_world_open_rules_each_reported(self):
        group = {
            "GroupId": "sg-006",
            "GroupName": "multi",
            "IpPermissions": [
                {"FromPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                {"FromPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
            ],
        }
        mock_client = MagicMock()
        mock_client.describe_security_groups.return_value = {"SecurityGroups": [group]}
        result = make_auditor(mock_client)._audit_security_groups()
        assert len(result) == 2

    def test_finding_includes_name_and_recommendation(self):
        mock_client = MagicMock()
        mock_client.describe_security_groups.return_value = {
            "SecurityGroups": [sg("sg-007", "my-sg", 22)]
        }
        finding = make_auditor(mock_client)._audit_security_groups()[0]
        assert finding["security_group_name"] == "my-sg"
        assert "recommendation" in finding
        assert "issue" in finding

    def test_empty_security_groups_returns_empty_list(self):
        mock_client = MagicMock()
        mock_client.describe_security_groups.return_value = {"SecurityGroups": []}
        assert make_auditor(mock_client)._audit_security_groups() == []


# ---------------------------------------------------------------------------
# audit() -- full run + summary
# ---------------------------------------------------------------------------

class TestAudit:
    def _make_clean_client(self):
        mock_client = MagicMock()
        mock_client.describe_instances.return_value = reservations(TAGGED_INSTANCE)
        mock_client.describe_security_groups.return_value = {"SecurityGroups": []}
        return mock_client

    def test_audit_returns_expected_keys(self):
        result = make_auditor(self._make_clean_client()).audit()
        assert "untagged_instances" in result
        assert "public_instances" in result
        assert "security_group_issues" in result
        assert "summary" in result

    def test_summary_total_is_sum_of_all_findings(self):
        mock_client = MagicMock()
        mock_client.describe_instances.return_value = reservations(
            {**UNTAGGED_INSTANCE, "PublicIpAddress": "1.2.3.4"}
        )
        mock_client.describe_security_groups.return_value = {
            "SecurityGroups": [sg("sg-x", "bad", 80)]
        }
        result = make_auditor(mock_client).audit()
        assert result["summary"]["total_findings"] == 3

    def test_summary_zero_when_all_clean(self):
        mock_client = MagicMock()
        mock_client.describe_instances.return_value = reservations(TAGGED_INSTANCE)
        mock_client.describe_security_groups.return_value = {"SecurityGroups": []}
        result = make_auditor(mock_client).audit()
        assert result["summary"]["total_findings"] == 0
        assert result["summary"]["critical"] == 0
        assert result["summary"]["high"] == 0

    def test_summary_critical_count(self):
        mock_client = MagicMock()
        mock_client.describe_instances.return_value = {"Reservations": []}
        mock_client.describe_security_groups.return_value = {
            "SecurityGroups": [
                sg("sg-a", "ssh", 22),
                sg("sg-b", "rdp", 3389),
                sg("sg-c", "http", 80),
            ]
        }
        result = make_auditor(mock_client).audit()
        assert result["summary"]["critical"] == 2
        assert result["summary"]["high"] == 1

    def test_summary_high_includes_untagged(self):
        mock_client = MagicMock()
        mock_client.describe_instances.return_value = reservations(UNTAGGED_INSTANCE)
        mock_client.describe_security_groups.return_value = {"SecurityGroups": []}
        result = make_auditor(mock_client).audit()
        assert result["summary"]["high"] == 1


# ---------------------------------------------------------------------------
# _count_severity
# ---------------------------------------------------------------------------

class TestCountSeverity:
    def test_counts_across_multiple_lists(self):
        mock_client = MagicMock()
        mock_client.describe_instances.return_value = {"Reservations": []}
        mock_client.describe_security_groups.return_value = {"SecurityGroups": []}
        auditor = make_auditor(mock_client)
        findings = {
            "list_a": [{"severity": "critical"}, {"severity": "high"}],
            "list_b": [{"severity": "critical"}],
            "summary": {},
        }
        assert auditor._count_severity(findings, "critical") == 2
        assert auditor._count_severity(findings, "high") == 1
        assert auditor._count_severity(findings, "medium") == 0

    def test_ignores_non_list_values(self):
        mock_client = MagicMock()
        mock_client.describe_instances.return_value = {"Reservations": []}
        mock_client.describe_security_groups.return_value = {"SecurityGroups": []}
        auditor = make_auditor(mock_client)
        findings = {"summary": {"total_findings": 5}, "items": [{"severity": "high"}]}
        assert auditor._count_severity(findings, "high") == 1
