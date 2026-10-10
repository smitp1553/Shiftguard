from shiftguard.parser import get_resources, get_all_resources


def test_nested_modules_are_flattened():
    root = {
        "resources": [{"address": "aws_iam_user.a", "type": "aws_iam_user"}],
        "child_modules": [
            {
                "resources": [{"address": "module.x.aws_iam_role.b", "type": "aws_iam_role"}],
                "child_modules": [
                    {"resources": [{"address": "module.x.module.y.aws_iam_policy.c", "type": "aws_iam_policy"}]}
                ],
            }
        ],
    }
    addresses = [r["address"] for r in get_resources(root)]
    assert addresses == [
        "aws_iam_user.a",
        "module.x.aws_iam_role.b",
        "module.x.module.y.aws_iam_policy.c",
    ]


def test_module_with_no_resources():
    assert get_resources({}) == []


def test_get_all_resources_reads_root_module():
    plan = {"planned_values": {"root_module": {"resources": [{"address": "aws_iam_user.test"}]}}}
    assert get_all_resources(plan) == [{"address": "aws_iam_user.test"}]