-- Copyright IBM Corp. 2020, 2026
-- SPDX-License-Identifier: BUSL-1.1

begin;

  -- Add Google Workspace Directory API configuration to OIDC auth methods.
  -- When google_workspace_service_account_json (encrypted) and
  -- google_workspace_admin_email are both set, Boundary performs a server-side
  -- call to the Google Admin SDK Directory API after OIDC token exchange to
  -- fetch the authenticating user's group memberships. Those group emails are
  -- injected into the userinfo claims as "groups" before managed-group filters
  -- are evaluated, enabling filters such as:
  --   "engineering@example.com" in "/userinfo/groups"
  alter table auth_oidc_method
    add column google_workspace_service_account_json bytea,
    add column google_workspace_admin_email text;

  -- Constraint: both fields must be set together or both null.
  alter table auth_oidc_method
    add constraint google_workspace_config_both_or_neither
      check (
        (google_workspace_service_account_json is null) = (google_workspace_admin_email is null)
      );

commit;
