const fs = require("fs");

const DEFAULT_USER_FILTER =
  "(&(objectCategory=person)(objectClass=user)(sAMAccountName={{username}})(!(userAccountControl:1.2.840.113556.1.4.803:=2)))";
const DEFAULT_USERNAME_ATTRIBUTE = "sAMAccountName";
const DEFAULT_TIMEOUT_MS = 5000;
// AD matching rule that resolves nested group membership server-side.
const LDAP_MATCHING_RULE_IN_CHAIN = "1.2.840.113556.1.4.1941";
const REQUIRED_ENV_KEYS = [
  "LDAP_URL",
  "LDAP_BIND_DN",
  "LDAP_BIND_PASSWORD",
  "LDAP_BASE_DN",
];

/**
 * Known failure reasons. These are only logged server-side and mapped to
 * generic client-facing messages by the login endpoint.
 */
const LDAP_ERROR_REASONS = {
  invalidCredentials: "invalid_credentials",
  userNotFound: "user_not_found",
  ambiguousUser: "ambiguous_user",
  notInGroup: "not_in_group",
  invalidUsername: "invalid_username",
  linkRefused: "link_refused",
  serverUnreachable: "server_unreachable",
  misconfigured: "misconfigured",
  directoryError: "directory_error",
};

class LdapAuthError extends Error {
  /**
   * @param {string} reason - One of LDAP_ERROR_REASONS
   * @param {string} [detail] - Server-side only detail for logs
   */
  constructor(reason, detail = null) {
    super(detail ? `${reason}: ${detail}` : reason);
    this.name = "LdapAuthError";
    this.reason = reason;
  }
}

/**
 * Reads a boolean-ish env flag. Presence enables it unless explicitly set to a falsy value.
 * @param {string} key
 * @returns {boolean}
 */
function envFlag(key) {
  if (!(key in process.env)) return false;
  return !["false", "0", "no", "off"].includes(
    String(process.env[key]).trim().toLowerCase()
  );
}

/**
 * Checks if Active Directory (LDAP) authentication is enabled and minimally configured.
 * @returns {boolean}
 */
function isLdapEnabled() {
  if (!envFlag("LDAP_ENABLED")) return false;
  return REQUIRED_ENV_KEYS.every((key) => !!process.env[key]);
}

/**
 * Local (non-LDAP) accounts may still log in with their password when this is set.
 * @returns {boolean}
 */
function ldapAllowLocalLogin() {
  return envFlag("LDAP_ALLOW_LOCAL_LOGIN");
}

/**
 * Short name of the AD domain, shown to users (eg: "DC=ad,DC=corp,DC=local" => "CORP").
 * LDAP_DOMAIN_NAME overrides the value derived from the domain components of LDAP_BASE_DN.
 * @returns {string|null}
 */
function ldapDomainName() {
  if (process.env.LDAP_DOMAIN_NAME) return process.env.LDAP_DOMAIN_NAME.trim();
  const domainComponents = String(process.env.LDAP_BASE_DN || "")
    .split(",")
    .map((part) => part.trim().match(/^DC=(.+)$/i)?.[1])
    .filter(Boolean);
  if (!domainComponents.length) return null;
  // The label just before the top-level domain is the domain name (ad.corp.local => corp).
  const name =
    domainComponents.length > 1
      ? domainComponents[domainComponents.length - 2]
      : domainComponents[0];
  return name.toUpperCase();
}

/**
 * Label shown on the login screen. {{AD_NAME}} is replaced by the AD domain name.
 * @returns {string|null}
 */
function ldapLoginLabel() {
  const label = process.env.LDAP_LOGIN_LABEL;
  if (!label) return null;
  return label
    .replace(/\{\{\s*AD[_ ]NAME\s*\}\}/gi, ldapDomainName() || "")
    .trim();
}

/**
 * When set, the role of LDAP users is recomputed from AD groups on each login
 * and cannot be edited from AnythingLLM.
 * @returns {boolean}
 */
function ldapRoleSyncEnabled() {
  return envFlag("LDAP_SYNC_ROLE_ON_LOGIN");
}

/**
 * When set, an existing local user with the same username is linked to AD on first AD login.
 * @returns {boolean}
 */
function ldapLinkExistingUsers() {
  return envFlag("LDAP_LINK_EXISTING_USERS");
}

/**
 * Builds the LDAP configuration from the environment.
 * @returns {{
 *  urls: string[],
 *  bindDN: string,
 *  bindPassword: string,
 *  baseDN: string,
 *  userFilter: string,
 *  usernameAttribute: string,
 *  requiredGroupDN: string|null,
 *  adminGroupDN: string|null,
 *  managerGroupDN: string|null,
 *  startTLS: boolean,
 *  timeout: number,
 *  tlsOptions: import("tls").ConnectionOptions,
 * }}
 */
function getLdapConfig() {
  const missing = REQUIRED_ENV_KEYS.filter((key) => !process.env[key]);
  if (missing.length > 0)
    throw new LdapAuthError(
      LDAP_ERROR_REASONS.misconfigured,
      `Missing required env: ${missing.join(", ")}`
    );

  const urls = String(process.env.LDAP_URL)
    .split(",")
    .map((url) => url.trim())
    .filter(Boolean);
  const userFilter = process.env.LDAP_USER_FILTER || DEFAULT_USER_FILTER;
  if (!userFilter.includes("{{username}}"))
    throw new LdapAuthError(
      LDAP_ERROR_REASONS.misconfigured,
      "LDAP_USER_FILTER must contain the {{username}} placeholder"
    );

  // Certificates are always verified unless explicitly disabled (test environments only).
  const tlsOptions = {
    rejectUnauthorized:
      !("LDAP_TLS_REJECT_UNAUTHORIZED" in process.env) ||
      envFlag("LDAP_TLS_REJECT_UNAUTHORIZED"),
  };
  if (process.env.LDAP_TLS_CA_PATH) {
    try {
      tlsOptions.ca = [fs.readFileSync(process.env.LDAP_TLS_CA_PATH)];
    } catch (e) {
      throw new LdapAuthError(
        LDAP_ERROR_REASONS.misconfigured,
        `Could not read LDAP_TLS_CA_PATH: ${e.message}`
      );
    }
  }

  const timeout = Number(process.env.LDAP_TIMEOUT_MS);
  return {
    urls,
    bindDN: process.env.LDAP_BIND_DN,
    bindPassword: process.env.LDAP_BIND_PASSWORD,
    baseDN: process.env.LDAP_BASE_DN,
    userFilter,
    usernameAttribute:
      process.env.LDAP_USERNAME_ATTRIBUTE || DEFAULT_USERNAME_ATTRIBUTE,
    requiredGroupDN: process.env.LDAP_REQUIRED_GROUP_DN || null,
    adminGroupDN: process.env.LDAP_ADMIN_GROUP_DN || null,
    managerGroupDN: process.env.LDAP_MANAGER_GROUP_DN || null,
    startTLS: envFlag("LDAP_STARTTLS"),
    timeout:
      Number.isFinite(timeout) && timeout > 0 ? timeout : DEFAULT_TIMEOUT_MS,
    tlsOptions,
  };
}

/**
 * Escapes a value for use inside an LDAP search filter (RFC 4515).
 * @param {string} value
 * @returns {string}
 */
function escapeFilterValue(value = "") {
  return String(value).replace(/[\\*()\0]/g, (char) => {
    return "\\" + char.charCodeAt(0).toString(16).padStart(2, "0");
  });
}

/**
 * Builds the user search filter with the escaped username.
 * @param {string} template
 * @param {string} username
 * @returns {string}
 */
function buildUserFilter(template, username) {
  const escaped = escapeFilterValue(username);
  return template.replace(/\{\{username\}\}/g, () => escaped);
}

/**
 * Extracts the AD sub-error code (eg: 52e, 773, 775) from a bind error message.
 * @param {Error} error
 * @returns {string|null}
 */
function adErrorCode(error) {
  const match = String(error?.message || "").match(/data ([0-9a-f]{3,4})/i);
  return match ? match[1] : null;
}

function firstValue(value) {
  if (Array.isArray(value)) return value[0] ?? null;
  return value ?? null;
}

function isResultCodeError(error) {
  const { ResultCodeError } = require("ldapts");
  return error instanceof ResultCodeError;
}

/**
 * Opens a connection on the first reachable LDAP_URL and runs the handler with it.
 * Only connection-level failures fail over to the next URL; directory responses
 * (eg: invalid credentials) are returned as-is.
 * @template T
 * @param {ReturnType<typeof getLdapConfig>} config
 * @param {(client: import("ldapts").Client) => Promise<T>} handler
 * @returns {Promise<T>}
 */
async function withConnection(config, handler) {
  const { Client } = require("ldapts");
  let lastError = null;

  for (const url of config.urls) {
    // ldapts opens a TLS socket whenever tlsOptions is set, even for ldap:// URLs,
    // so only pass them for ldaps:// (StartTLS receives them separately below).
    const client = new Client({
      url,
      timeout: config.timeout,
      connectTimeout: config.timeout,
      ...(url.toLowerCase().startsWith("ldaps://")
        ? { tlsOptions: config.tlsOptions }
        : {}),
    });

    try {
      if (config.startTLS) await client.startTLS(config.tlsOptions);
      return await handler(client);
    } catch (error) {
      if (error instanceof LdapAuthError || isResultCodeError(error))
        throw error;
      lastError = error;
      console.error(
        `[LDAP] Connection to ${url} failed: ${error?.message || error}`
      );
    } finally {
      try {
        await client.unbind();
      } catch {}
    }
  }

  throw new LdapAuthError(
    LDAP_ERROR_REASONS.serverUnreachable,
    lastError?.message || "No LDAP server reachable"
  );
}

async function bindServiceAccount(client, config) {
  try {
    await client.bind(config.bindDN, config.bindPassword);
  } catch (error) {
    if (isResultCodeError(error))
      throw new LdapAuthError(
        LDAP_ERROR_REASONS.misconfigured,
        `Service account bind failed (${adErrorCode(error) || error.code})`
      );
    throw error;
  }
}

/**
 * Finds exactly one user entry for the given username.
 * @returns {Promise<import("ldapts").Entry>}
 */
async function findUserEntry(client, config, username) {
  const { SizeLimitExceededError } = require("ldapts");
  let searchEntries = [];
  try {
    ({ searchEntries } = await client.search(config.baseDN, {
      scope: "sub",
      filter: buildUserFilter(config.userFilter, username),
      attributes: [
        "objectGUID",
        config.usernameAttribute,
        "userPrincipalName",
        "displayName",
        "mail",
      ],
      explicitBufferAttributes: ["objectGUID"],
      sizeLimit: 2,
    }));
  } catch (error) {
    if (error instanceof SizeLimitExceededError)
      throw new LdapAuthError(LDAP_ERROR_REASONS.ambiguousUser, username);
    throw error;
  }

  if (searchEntries.length === 0)
    throw new LdapAuthError(LDAP_ERROR_REASONS.userNotFound, username);
  if (searchEntries.length > 1)
    throw new LdapAuthError(LDAP_ERROR_REASONS.ambiguousUser, username);
  return searchEntries[0];
}

/**
 * Checks if the user DN is a (direct or nested) member of the group DN.
 * @returns {Promise<boolean>}
 */
async function isMemberOf(client, userDN, groupDN) {
  if (!groupDN) return false;
  const { searchEntries } = await client.search(userDN, {
    scope: "base",
    filter: `(memberOf:${LDAP_MATCHING_RULE_IN_CHAIN}:=${escapeFilterValue(groupDN)})`,
    attributes: ["distinguishedName"],
  });
  return searchEntries.length > 0;
}

/**
 * Computes the AnythingLLM role from group membership.
 * @param {{admin: boolean, manager: boolean}} membership
 * @returns {"admin"|"manager"|"default"}
 */
function roleFromMembership({ admin = false, manager = false } = {}) {
  if (admin) return "admin";
  if (manager) return "manager";
  return "default";
}

/**
 * Normalizes the directory username into an AnythingLLM username.
 * @param {string} value
 * @returns {string}
 */
function normalizeUsername(value) {
  const { User } = require("../../../models/user");
  try {
    return User.validations.username(String(value || "").toLowerCase());
  } catch (e) {
    throw new LdapAuthError(
      LDAP_ERROR_REASONS.invalidUsername,
      `${value}: ${e.message}`
    );
  }
}

/**
 * Resolves the user profile (identity, groups, role) for an entry using the service account binding.
 */
async function resolveProfile(client, config, entry) {
  const guid = firstValue(entry.objectGUID);
  if (!guid || !Buffer.isBuffer(guid) || guid.length === 0)
    throw new LdapAuthError(
      LDAP_ERROR_REASONS.misconfigured,
      `No objectGUID returned for ${entry.dn}`
    );

  const [required, admin, manager] = await Promise.all([
    config.requiredGroupDN
      ? isMemberOf(client, entry.dn, config.requiredGroupDN)
      : Promise.resolve(true),
    isMemberOf(client, entry.dn, config.adminGroupDN),
    isMemberOf(client, entry.dn, config.managerGroupDN),
  ]);

  return {
    externalId: guid.toString("base64"),
    dn: entry.dn,
    username: normalizeUsername(firstValue(entry[config.usernameAttribute])),
    displayName: firstValue(entry.displayName),
    email: firstValue(entry.mail),
    authorized: required,
    groups: { required, admin, manager },
    role: roleFromMembership({ admin, manager }),
  };
}

/**
 * Authenticates a user against Active Directory.
 * @param {string} rawUsername
 * @param {string} password
 * @returns {Promise<{externalId: string, dn: string, username: string, displayName: string|null, email: string|null, role: string}>}
 * @throws {LdapAuthError}
 */
async function authenticate(rawUsername, password) {
  const username = String(rawUsername ?? "").trim();
  // An empty password results in an unauthenticated (anonymous) bind that AD accepts.
  // This must be rejected before any network call.
  if (!username || typeof password !== "string" || password.length === 0)
    throw new LdapAuthError(LDAP_ERROR_REASONS.invalidCredentials);

  const config = getLdapConfig();
  return await withConnection(config, async (client) => {
    await bindServiceAccount(client, config);
    const entry = await findUserEntry(client, config, username);

    try {
      await client.bind(entry.dn, password);
    } catch (error) {
      if (isResultCodeError(error))
        throw new LdapAuthError(
          LDAP_ERROR_REASONS.invalidCredentials,
          `${username} (${adErrorCode(error) || error.code})`
        );
      throw error;
    }

    // Group lookups are done as the service account since users may not be able to read them.
    await bindServiceAccount(client, config);
    const profile = await resolveProfile(client, config, entry);
    if (!profile.authorized)
      throw new LdapAuthError(LDAP_ERROR_REASONS.notInGroup, username);

    const { authorized: _authorized, groups: _groups, ...rest } = profile;
    return rest;
  });
}

/**
 * Looks up a user by username without binding as them. Used by the admin diagnostic endpoint.
 * @param {string} rawUsername
 */
async function lookupUser(rawUsername) {
  const username = String(rawUsername ?? "").trim();
  if (!username) throw new LdapAuthError(LDAP_ERROR_REASONS.userNotFound);

  const config = getLdapConfig();
  return await withConnection(config, async (client) => {
    await bindServiceAccount(client, config);
    const entry = await findUserEntry(client, config, username);
    const { externalId: _externalId, ...profile } = await resolveProfile(
      client,
      config,
      entry
    );
    return profile;
  });
}

/**
 * Looks up a user by objectGUID (base64). Returns null when the user no longer
 * exists or no longer matches LDAP_USER_FILTER (eg: disabled account).
 * @param {string} externalId
 */
async function lookupUserByExternalId(externalId) {
  const config = getLdapConfig();
  const guid = Buffer.from(String(externalId), "base64");
  const guidFilter = Array.from(guid)
    .map((byte) => "\\" + byte.toString(16).padStart(2, "0"))
    .join("");

  const attributes = [
    "objectGUID",
    config.usernameAttribute,
    "displayName",
    "mail",
  ];

  return await withConnection(config, async (client) => {
    await bindServiceAccount(client, config);
    const { searchEntries } = await client.search(config.baseDN, {
      scope: "sub",
      filter: `(objectGUID=${guidFilter})`,
      attributes,
      explicitBufferAttributes: ["objectGUID"],
      sizeLimit: 1,
    });
    if (searchEntries.length === 0) return null;

    // Re-apply the configured user filter (which excludes disabled accounts by default).
    const username = String(
      firstValue(searchEntries[0][config.usernameAttribute]) || ""
    );
    const userFilter = buildUserFilter(config.userFilter, username);
    const { searchEntries: matching } = await client.search(config.baseDN, {
      scope: "sub",
      filter: `(&(objectGUID=${guidFilter})${userFilter})`,
      attributes,
      explicitBufferAttributes: ["objectGUID"],
      sizeLimit: 1,
    });
    if (matching.length === 0) return null;
    return await resolveProfile(client, config, matching[0]);
  });
}

/**
 * Checks connectivity and the service account credentials.
 * @returns {Promise<{success: boolean, error: string|null}>}
 */
async function testConnection() {
  try {
    const config = getLdapConfig();
    await withConnection(config, (client) =>
      bindServiceAccount(client, config)
    );
    return { success: true, error: null };
  } catch (error) {
    return { success: false, error: error.reason || error.message };
  }
}

/**
 * Logs configuration problems on boot so a misconfiguration is visible before the first login.
 */
async function logLdapBootStatus() {
  if (!envFlag("LDAP_ENABLED")) return;
  const prefix = "\x1b[36m[ActiveDirectory]\x1b[0m";
  try {
    const config = getLdapConfig();
    const { SystemSettings } = require("../../../models/systemSettings");
    if (!(await SystemSettings.isMultiUserMode()))
      console.warn(
        `${prefix} LDAP_ENABLED is set but multi-user mode is disabled - Active Directory login is inactive.`
      );
    if (
      config.urls.some((url) => url.startsWith("ldap://")) &&
      !config.startTLS
    )
      console.warn(
        `${prefix} Unencrypted ldap:// URL without LDAP_STARTTLS - passwords are sent in clear text.`
      );
    if (!config.tlsOptions.rejectUnauthorized)
      console.warn(
        `${prefix} LDAP_TLS_REJECT_UNAUTHORIZED is disabled - do not use this in production.`
      );
    console.log(`${prefix} Active Directory authentication enabled.`);
  } catch (e) {
    console.error(
      `${prefix} Active Directory authentication is misconfigured: ${e.message}`
    );
  }
}

module.exports = {
  LDAP_ERROR_REASONS,
  LdapAuthError,
  isLdapEnabled,
  ldapAllowLocalLogin,
  ldapRoleSyncEnabled,
  ldapLinkExistingUsers,
  ldapDomainName,
  ldapLoginLabel,
  getLdapConfig,
  escapeFilterValue,
  buildUserFilter,
  roleFromMembership,
  authenticate,
  lookupUser,
  lookupUserByExternalId,
  testConnection,
  logLdapBootStatus,
};
