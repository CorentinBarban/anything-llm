jest.mock("../../utils/prisma", () => ({
  users: {
    findUnique: jest.fn(),
    findFirst: jest.fn(),
    update: jest.fn(async ({ where, data }) => ({ id: where.id, ...data })),
    create: jest.fn(async ({ data }) => ({ id: 99, ...data })),
  },
}));
jest.mock("../../models/eventLogs", () => ({
  EventLogs: { logEvent: jest.fn() },
}));

const prisma = require("../../utils/prisma");
const { User } = require("../../models/user");
const { LDAP_ERROR_REASONS } = require("../../utils/auth/ldap");

const PROFILE = { externalId: "guid==", username: "jdoe", role: "manager" };

describe("User LDAP support", () => {
  const ORIGINAL_ENV = { ...process.env };

  beforeEach(() => {
    jest.clearAllMocks();
    process.env = { ...ORIGINAL_ENV };
    delete process.env.LDAP_SYNC_ROLE_ON_LOGIN;
    delete process.env.LDAP_LINK_EXISTING_USERS;
    prisma.users.findUnique.mockResolvedValue(null);
    prisma.users.findFirst.mockResolvedValue(null);
  });

  afterAll(() => {
    process.env = ORIGINAL_ENV;
  });

  describe("upsertFromLdap", () => {
    it("creates a new LDAP user with an unusable password", async () => {
      const { user, created } = await User.upsertFromLdap(PROFILE);
      expect(created).toBe(true);
      expect(user).toMatchObject({
        username: "jdoe",
        role: "manager",
        auth_provider: "ldap",
        external_id: "guid==",
        seen_recovery_codes: true,
      });
      expect(user.password).toMatch(/^\$2[aby]\$/);
    });

    it("finds users by external_id and follows username changes", async () => {
      prisma.users.findUnique.mockImplementation(async ({ where }) =>
        where.external_id
          ? { id: 1, username: "old.name", role: "default", auth_provider: "ldap" }
          : null
      );
      const { user, created } = await User.upsertFromLdap(PROFILE);
      expect(created).toBe(false);
      expect(prisma.users.update).toHaveBeenCalledWith({
        where: { id: 1 },
        data: expect.objectContaining({ username: "jdoe" }),
      });
      // Role is only synced when LDAP_SYNC_ROLE_ON_LOGIN is set.
      expect(user.role).toBeUndefined();
    });

    it("syncs the role when LDAP_SYNC_ROLE_ON_LOGIN is set", async () => {
      process.env.LDAP_SYNC_ROLE_ON_LOGIN = "1";
      prisma.users.findUnique.mockImplementation(async ({ where }) =>
        where.external_id
          ? { id: 1, username: "jdoe", role: "default", auth_provider: "ldap" }
          : null
      );
      const { user } = await User.upsertFromLdap(PROFILE);
      expect(user.role).toBe("manager");
    });

    it("refuses to rename onto a username owned by another user", async () => {
      prisma.users.findUnique.mockImplementation(async ({ where }) =>
        where.external_id ? { id: 1, username: "old.name" } : null
      );
      prisma.users.findFirst.mockResolvedValue({ id: 2, username: "jdoe" });
      await expect(User.upsertFromLdap(PROFILE)).rejects.toMatchObject({
        reason: LDAP_ERROR_REASONS.linkRefused,
      });
    });

    it("does not take over an existing local user by default", async () => {
      prisma.users.findUnique.mockImplementation(async ({ where }) =>
        where.username ? { id: 3, username: "jdoe", auth_provider: "local" } : null
      );
      await expect(User.upsertFromLdap(PROFILE)).rejects.toMatchObject({
        reason: LDAP_ERROR_REASONS.linkRefused,
      });
      expect(prisma.users.update).not.toHaveBeenCalled();
    });

    it("links an existing local user when LDAP_LINK_EXISTING_USERS is set", async () => {
      process.env.LDAP_LINK_EXISTING_USERS = "1";
      prisma.users.findUnique.mockImplementation(async ({ where }) =>
        where.username
          ? { id: 3, username: "jdoe", auth_provider: "local", password: "old" }
          : null
      );
      const { user } = await User.upsertFromLdap(PROFILE);
      expect(user).toMatchObject({
        id: 3,
        auth_provider: "ldap",
        external_id: "guid==",
      });
      expect(user.password).not.toBe("old");
    });

    it("never links another LDAP account with the same username", async () => {
      process.env.LDAP_LINK_EXISTING_USERS = "1";
      prisma.users.findUnique.mockImplementation(async ({ where }) =>
        where.username
          ? { id: 4, username: "jdoe", auth_provider: "ldap", external_id: "other" }
          : null
      );
      await expect(User.upsertFromLdap(PROFILE)).rejects.toMatchObject({
        reason: LDAP_ERROR_REASONS.linkRefused,
      });
    });
  });

  describe("ldapLockedChange", () => {
    const ldapUser = { auth_provider: "ldap", username: "jdoe", role: "default" };

    it("allows any change on local users", () => {
      expect(
        User.ldapLockedChange({ ...ldapUser, auth_provider: "local" }, {
          password: "new",
          username: "other",
        })
      ).toBeNull();
    });

    it("locks username and password of LDAP users", () => {
      expect(User.ldapLockedChange(ldapUser, { password: "new" })).toBe(
        "password"
      );
      expect(User.ldapLockedChange(ldapUser, { username: "other" })).toBe(
        "username"
      );
      expect(
        User.ldapLockedChange(ldapUser, { username: "jdoe", bio: "hi" })
      ).toBeNull();
      expect(User.ldapLockedChange(ldapUser, { password: "" })).toBeNull();
    });

    it("locks the role only when roles are synced from AD", () => {
      expect(User.ldapLockedChange(ldapUser, { role: "admin" })).toBeNull();
      process.env.LDAP_SYNC_ROLE_ON_LOGIN = "1";
      expect(User.ldapLockedChange(ldapUser, { role: "admin" })).toBe("role");
      expect(User.ldapLockedChange(ldapUser, { role: "default" })).toBeNull();
    });

    it("hides external_id from filtered user objects", () => {
      expect(
        User.filterFields({ ...ldapUser, external_id: "x", password: "y" })
      ).toEqual(ldapUser);
    });
  });
});
