const { log, conclude } = require("./helpers/index.js");
const { User } = require("../models/user.js");
const { EventLogs } = require("../models/eventLogs.js");
const {
  isLdapEnabled,
  ldapRoleSyncEnabled,
  lookupUserByExternalId,
  LdapAuthError,
  LDAP_ERROR_REASONS,
} = require("../utils/auth/ldap");

// Sessions are long-lived JWTs, so accounts disabled or removed from the required group in
// Active Directory are suspended here, which invalidates their session on the next request.
// Suspended users are never automatically unsuspended - an admin must do it.
(async () => {
  try {
    if (!isLdapEnabled()) {
      log("Active Directory authentication is not enabled - skipping.");
      return;
    }

    const users = await User._where({ auth_provider: "ldap", suspended: 0 });
    let suspendedCount = 0;
    let failedCount = 0;

    for (const user of users) {
      if (!user.external_id) continue;
      try {
        const profile = await lookupUserByExternalId(user.external_id);
        if (!profile || !profile.authorized) {
          await User._update(user.id, {
            suspended: 1,
            last_ldap_sync: new Date(),
          });
          await EventLogs.logEvent(
            "ldap_user_suspended",
            {
              username: user.username,
              reason: profile ? "not_in_group" : "disabled_or_removed",
            },
            user.id
          );
          suspendedCount++;
          continue;
        }

        const data = { last_ldap_sync: new Date() };
        if (ldapRoleSyncEnabled() && profile.role !== user.role)
          data.role = profile.role;
        await User._update(user.id, data);
      } catch (e) {
        // Never suspend users because the directory cannot be reached.
        if (
          e instanceof LdapAuthError &&
          [
            LDAP_ERROR_REASONS.serverUnreachable,
            LDAP_ERROR_REASONS.misconfigured,
          ].includes(e.reason)
        ) {
          log(`Aborting Active Directory sync: ${e.message}`);
          return;
        }
        failedCount++;
        log(`Could not sync user ${user.username}: ${e.message}`);
      }
    }

    log(
      `Active Directory sync complete: ${users.length} checked, ${suspendedCount} suspended, ${failedCount} failed.`
    );
  } catch (e) {
    console.error(e);
    log(`errored with ${e.message}`);
  } finally {
    conclude();
  }
})();
