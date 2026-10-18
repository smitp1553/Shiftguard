# the order matters: if two techniques give the same step, the first one in this list is the one reported
from shiftguard.techniques import (
    create_policy_version,
    attach_user_policy,
    put_user_policy,
    attach_role_policy,
    put_role_policy,
    add_user_to_group,
    set_default_policy_version,
    assume_role,
    create_access_key,
    login_profile,
    passrole_ec2,
    passrole_lambda,
    update_assume_role_policy,
)

ALL = [
    create_policy_version,
    attach_user_policy,
    put_user_policy,
    attach_role_policy,
    put_role_policy,
    add_user_to_group,
    set_default_policy_version,
    assume_role,
    create_access_key,
    login_profile,
    passrole_ec2,
    passrole_lambda,
    update_assume_role_policy,
]
