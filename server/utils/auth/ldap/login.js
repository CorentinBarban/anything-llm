const { User } = require("../../../models/user");
const { Workspace } = require("../../../models/workspace");
const { EventLogs } = require("../../../models/eventLogs");
const { Telemetry } = require("../../../models/telemetry");
const { makeJWT } = require("../../http");
const { authenticate, LdapAuthError, LDAP_ERROR_REASONS } = require("./index");

/**
 * Maps internal failure reasons to client-facing responses.
 * Reasons that happen before the password is verified all share the same message
 * so the response does not reveal whether a username exists.
 * @param {string} reason
 * @returns {{status: number, message: string}}
 */
function failureResponse(reason) {
  switch (reason) {
    case LDAP_ERROR_REASONS.invalidCredentials:
    case LDAP_ERROR_REASONS.userNotFound:
    case LDAP_ERROR_REASONS.ambiguousUser:
      return { status: 200, message: "[006] Invalid login credentials." };
    case LDAP_ERROR_REASONS.notInGroup:
      return {
        status: 200,
        message: "[007] You are not authorized to access this instance.",
      };
    case LDAP_ERROR_REASONS.linkRefused:
    case LDAP_ERROR_REASONS.invalidUsername:
      return {
        status: 200,
        message:
          "[009] Your directory account cannot be linked to this instance. Contact your administrator.",
      };
    default:
      return {
        status: 503,
        message: "[008] Authentication server unavailable.",
      };
  }
}

/**
 * Creates a personal workspace for a newly provisioned AD user, with the user as its only member.
 * Never throws: a failure here must not block the login.
 * @param {Object} user
 * @param {{displayName?: string|null}} profile
 */
async function createPersonalWorkspace(user, profile) {
  try {
    const { workspace, message } = await Workspace.new(
      profile?.displayName || user.username,
      user.id
    );
    if (!workspace) throw new Error(message);
    await EventLogs.logEvent(
      "workspace_created",
      { workspaceName: workspace.name, provider: "ldap" },
      user.id
    );
  } catch (error) {
    console.error(
      `[LDAP] Could not create workspace for "${user.username}": ${error.message}`
    );
  }
}

/**
 * Handles a multi-user login request against Active Directory.
 * Responds with the same payload shape as the local /request-token flow.
 * @param {import("express").Request} request
 * @param {import("express").Response} response
 * @param {{username: string, password: string}} credentials
 */
async function ldapLogin(request, response, { username, password }) {
  const ip = request.ip || "Unknown IP";
  try {
    const profile = await authenticate(username, password);
    const { user, created } = await User.upsertFromLdap(profile);

    if (user.suspended) {
      await EventLogs.logEvent(
        "failed_login_account_suspended",
        { ip, username: user.username, provider: "ldap" },
        user.id
      );
      response.status(200).json({
        user: null,
        valid: false,
        token: null,
        message: "[004] Account suspended by admin.",
      });
      return;
    }

    if (created) {
      await EventLogs.logEvent(
        "ldap_user_provisioned",
        { username: user.username, role: user.role },
        user.id
      );
      await createPersonalWorkspace(user, profile);
    }
    await Telemetry.sendTelemetry(
      "login_event",
      { multiUserMode: true, provider: "ldap" },
      user.id
    );
    await EventLogs.logEvent(
      "login_event",
      { ip, username: user.username, provider: "ldap" },
      user.id
    );

    response.status(200).json({
      valid: true,
      user: User.filterFields(user),
      token: makeJWT(
        { id: user.id, username: user.username },
        process.env.JWT_EXPIRY
      ),
      message: null,
    });
  } catch (error) {
    const reason =
      error instanceof LdapAuthError
        ? error.reason
        : LDAP_ERROR_REASONS.directoryError;
    console.error(
      `[LDAP] Login failed for "${String(username)}": ${error.message}`
    );
    await EventLogs.logEvent("failed_login_ldap", {
      ip,
      username: String(username || "Unknown user"),
      reason,
    });

    const { status, message } = failureResponse(reason);
    response.status(status).json({
      user: null,
      valid: false,
      token: null,
      message,
    });
  }
}

module.exports = { ldapLogin, failureResponse };
