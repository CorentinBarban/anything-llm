jest.mock("ldapts", () => {
  const actual = jest.requireActual("ldapts");
  return { ...actual, Client: jest.fn() };
});

const {
  Client,
  InvalidCredentialsError,
  SizeLimitExceededError,
} = require("ldapts");
const {
  authenticate,
  escapeFilterValue,
  buildUserFilter,
  roleFromMembership,
  isLdapEnabled,
  LDAP_ERROR_REASONS,
} = require("../../../utils/auth/ldap");

const USER_DN = "CN=Jane Doe,OU=Users,DC=corp,DC=local";
const GUID = Buffer.from("0123456789abcdef");
const BASE_ENV = {
  LDAP_ENABLED: "1",
  LDAP_URL: "ldaps://dc01.corp.local:636",
  LDAP_BIND_DN: "CN=svc,DC=corp,DC=local",
  LDAP_BIND_PASSWORD: "svc-password",
  LDAP_BASE_DN: "DC=corp,DC=local",
};

/**
 * Builds a mocked ldapts client.
 * @param {Object} opts
 * @param {Object[]} [opts.entries] - entries returned by the user search
 * @param {string[]} [opts.memberOf] - group DNs the user is a (nested) member of
 * @param {string} [opts.userPassword] - the valid password for the user
 */
function mockClient({
  entries = [
    { dn: USER_DN, objectGUID: GUID, sAMAccountName: "JDoe", mail: "j@corp" },
  ],
  memberOf = [],
  userPassword = "secret",
  searchError = null,
} = {}) {
  const client = {
    startTLS: jest.fn().mockResolvedValue(),
    unbind: jest.fn().mockResolvedValue(),
    bind: jest.fn(async (dn, password) => {
      if (dn === BASE_ENV.LDAP_BIND_DN && password === "svc-password") return;
      if (dn === USER_DN && password === userPassword) return;
      throw new InvalidCredentialsError(
        "80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 52e, v4563"
      );
    }),
    search: jest.fn(async (base, options) => {
      if (options.scope === "base") {
        const isMember = memberOf.some((group) =>
          options.filter.includes(escapeFilterValue(group))
        );
        return { searchEntries: isMember ? [{ dn: base }] : [] };
      }
      if (searchError) throw searchError;
      return { searchEntries: entries };
    }),
  };
  Client.mockImplementation(() => client);
  return client;
}

describe("LDAP authentication", () => {
  const ORIGINAL_ENV = { ...process.env };

  beforeEach(() => {
    jest.clearAllMocks();
    jest.spyOn(console, "error").mockImplementation(() => {});
    process.env = { ...ORIGINAL_ENV, ...BASE_ENV };
  });

  afterEach(() => {
    process.env = ORIGINAL_ENV;
    console.error.mockRestore();
  });

  describe("escapeFilterValue / buildUserFilter", () => {
    it("escapes RFC 4515 special characters", () => {
      expect(escapeFilterValue("*)(uid=*")).toBe("\\2a\\29\\28uid=\\2a");
      expect(escapeFilterValue("a\\b")).toBe("a\\5cb");
      expect(escapeFilterValue("a\0b")).toBe("a\\00b");
      expect(escapeFilterValue("jane.doe")).toBe("jane.doe");
    });

    it("injects the escaped username into every placeholder", () => {
      expect(
        buildUserFilter("(|(uid={{username}})(mail={{username}}))", "a*$&")
      ).toBe("(|(uid=a\\2a$&)(mail=a\\2a$&))");
    });
  });

  describe("isLdapEnabled", () => {
    it("requires the flag and all mandatory settings", () => {
      expect(isLdapEnabled()).toBe(true);
      delete process.env.LDAP_BIND_PASSWORD;
      expect(isLdapEnabled()).toBe(false);
      process.env.LDAP_BIND_PASSWORD = "x";
      process.env.LDAP_ENABLED = "false";
      expect(isLdapEnabled()).toBe(false);
    });
  });

  describe("roleFromMembership", () => {
    it("gives admin precedence over manager", () => {
      expect(roleFromMembership({ admin: true, manager: true })).toBe("admin");
      expect(roleFromMembership({ manager: true })).toBe("manager");
      expect(roleFromMembership({})).toBe("default");
    });
  });

  describe("authenticate", () => {
    it("rejects empty passwords without any network call (anonymous bind)", async () => {
      mockClient();
      await expect(authenticate("jdoe", "")).rejects.toMatchObject({
        reason: LDAP_ERROR_REASONS.invalidCredentials,
      });
      await expect(authenticate("jdoe", undefined)).rejects.toMatchObject({
        reason: LDAP_ERROR_REASONS.invalidCredentials,
      });
      expect(Client).not.toHaveBeenCalled();
    });

    it("returns the profile for valid credentials", async () => {
      process.env.LDAP_ADMIN_GROUP_DN = "CN=Admins,DC=corp,DC=local";
      process.env.LDAP_MANAGER_GROUP_DN = "CN=Managers,DC=corp,DC=local";
      const client = mockClient({ memberOf: ["CN=Managers,DC=corp,DC=local"] });

      const profile = await authenticate("JDoe", "secret");
      expect(profile).toEqual({
        externalId: GUID.toString("base64"),
        dn: USER_DN,
        username: "jdoe",
        displayName: null,
        email: "j@corp",
        role: "manager",
      });
      expect(client.bind).toHaveBeenCalledWith(USER_DN, "secret");
      expect(client.unbind).toHaveBeenCalled();
    });

    it("escapes the username in the search filter", async () => {
      const client = mockClient();
      await authenticate("*)(sAMAccountName=*", "secret").catch(() => {});
      const { filter } = client.search.mock.calls[0][1];
      expect(filter).toContain("sAMAccountName=\\2a\\29\\28sAMAccountName=\\2a");
    });

    it("rejects an invalid password", async () => {
      mockClient();
      await expect(authenticate("jdoe", "wrong")).rejects.toMatchObject({
        reason: LDAP_ERROR_REASONS.invalidCredentials,
      });
    });

    it("rejects unknown and ambiguous users", async () => {
      mockClient({ entries: [] });
      await expect(authenticate("ghost", "secret")).rejects.toMatchObject({
        reason: LDAP_ERROR_REASONS.userNotFound,
      });

      mockClient({ searchError: new SizeLimitExceededError() });
      await expect(authenticate("j*", "secret")).rejects.toMatchObject({
        reason: LDAP_ERROR_REASONS.ambiguousUser,
      });
    });

    it("rejects users outside of the required group", async () => {
      process.env.LDAP_REQUIRED_GROUP_DN = "CN=Users,DC=corp,DC=local";
      mockClient({ memberOf: [] });
      await expect(authenticate("jdoe", "secret")).rejects.toMatchObject({
        reason: LDAP_ERROR_REASONS.notInGroup,
      });

      mockClient({ memberOf: ["CN=Users,DC=corp,DC=local"] });
      await expect(authenticate("jdoe", "secret")).resolves.toMatchObject({
        role: "default",
      });
    });

    it("reports a misconfigured service account", async () => {
      process.env.LDAP_BIND_PASSWORD = "wrong";
      mockClient();
      await expect(authenticate("jdoe", "secret")).rejects.toMatchObject({
        reason: LDAP_ERROR_REASONS.misconfigured,
      });
    });

    it("rejects directory usernames that are not valid AnythingLLM usernames", async () => {
      mockClient({
        entries: [{ dn: USER_DN, objectGUID: GUID, sAMAccountName: "1jdoe" }],
      });
      await expect(authenticate("1jdoe", "secret")).rejects.toMatchObject({
        reason: LDAP_ERROR_REASONS.invalidUsername,
      });
    });

    it("fails over to the next URL on connection errors only", async () => {
      process.env.LDAP_URL = "ldaps://dc01:636, ldaps://dc02:636";
      const working = mockClient();
      const broken = {
        ...working,
        bind: jest.fn().mockRejectedValue(new Error("connect ECONNREFUSED")),
      };
      Client.mockImplementationOnce(() => broken).mockImplementationOnce(
        () => working
      );

      await expect(authenticate("jdoe", "secret")).resolves.toMatchObject({
        username: "jdoe",
      });
      expect(Client.mock.calls.map(([opts]) => opts.url)).toEqual([
        "ldaps://dc01:636",
        "ldaps://dc02:636",
      ]);
    });

    it("reports the directory as unreachable when every URL fails", async () => {
      Client.mockImplementation(() => ({
        bind: jest.fn().mockRejectedValue(new Error("ETIMEDOUT")),
        unbind: jest.fn().mockResolvedValue(),
      }));
      await expect(authenticate("jdoe", "secret")).rejects.toMatchObject({
        reason: LDAP_ERROR_REASONS.serverUnreachable,
      });
    });

    it("verifies TLS certificates unless explicitly disabled", async () => {
      mockClient();
      await authenticate("jdoe", "secret");
      expect(Client.mock.calls[0][0].tlsOptions.rejectUnauthorized).toBe(true);

      process.env.LDAP_TLS_REJECT_UNAUTHORIZED = "false";
      Client.mockClear();
      await authenticate("jdoe", "secret");
      expect(Client.mock.calls[0][0].tlsOptions.rejectUnauthorized).toBe(false);
    });

    it("does not force TLS on plain ldap:// URLs", async () => {
      process.env.LDAP_URL = "ldap://dc01.corp.local:389";
      const client = mockClient();
      await authenticate("jdoe", "secret");
      expect(Client.mock.calls[0][0].tlsOptions).toBeUndefined();
      expect(client.startTLS).not.toHaveBeenCalled();
    });
  });
});
