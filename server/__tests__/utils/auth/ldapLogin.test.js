jest.mock("../../../utils/auth/ldap", () => {
  const actual = jest.requireActual("../../../utils/auth/ldap");
  return { ...actual, authenticate: jest.fn() };
});
jest.mock("../../../models/user", () => ({
  User: {
    upsertFromLdap: jest.fn(),
    filterFields: jest.fn(({ password: _p, ...rest }) => rest),
  },
}));
jest.mock("../../../models/workspace", () => ({
  Workspace: { new: jest.fn() },
}));
jest.mock("../../../models/eventLogs", () => ({
  EventLogs: { logEvent: jest.fn() },
}));
jest.mock("../../../models/telemetry", () => ({
  Telemetry: { sendTelemetry: jest.fn() },
}));

const {
  authenticate,
  LdapAuthError,
  LDAP_ERROR_REASONS,
} = require("../../../utils/auth/ldap");
const { User } = require("../../../models/user");
const { Workspace } = require("../../../models/workspace");
const { EventLogs } = require("../../../models/eventLogs");
const { ldapLogin } = require("../../../utils/auth/ldap/login");
const { decodeJWT } = require("../../../utils/http");

function mockResponse() {
  const response = {};
  response.status = jest.fn(() => response);
  response.json = jest.fn(() => response);
  return response;
}

describe("ldapLogin", () => {
  const request = { ip: "127.0.0.1" };
  const ORIGINAL_SECRET = process.env.JWT_SECRET;

  beforeAll(() => {
    process.env.JWT_SECRET = "test-secret";
  });
  afterAll(() => {
    process.env.JWT_SECRET = ORIGINAL_SECRET;
  });
  beforeEach(() => {
    jest.clearAllMocks();
    jest.spyOn(console, "error").mockImplementation(() => {});
  });
  afterEach(() => console.error.mockRestore());

  it("returns a session token for a valid AD user", async () => {
    authenticate.mockResolvedValue({ externalId: "g", username: "jdoe" });
    User.upsertFromLdap.mockResolvedValue({
      user: { id: 7, username: "jdoe", password: "x", suspended: 0 },
      created: true,
    });
    const response = mockResponse();

    await ldapLogin(request, response, { username: "JDoe", password: "pw" });

    expect(response.status).toHaveBeenCalledWith(200);
    const body = response.json.mock.calls[0][0];
    expect(body).toMatchObject({ valid: true, message: null });
    expect(body.user).toEqual({ id: 7, username: "jdoe", suspended: 0 });
    expect(decodeJWT(body.token)).toMatchObject({ id: 7, username: "jdoe" });
    expect(EventLogs.logEvent).toHaveBeenCalledWith(
      "ldap_user_provisioned",
      expect.any(Object),
      7
    );
  });

  it("creates a personal workspace only for newly provisioned users", async () => {
    authenticate.mockResolvedValue({
      externalId: "g",
      username: "jdoe",
      displayName: "John Doe",
    });
    Workspace.new.mockResolvedValue({ workspace: { id: 1, name: "John Doe" } });
    User.upsertFromLdap.mockResolvedValue({
      user: { id: 7, username: "jdoe", suspended: 0 },
      created: true,
    });
    await ldapLogin(request, mockResponse(), {
      username: "jdoe",
      password: "pw",
    });
    expect(Workspace.new).toHaveBeenCalledWith("John Doe", 7);

    Workspace.new.mockClear();
    User.upsertFromLdap.mockResolvedValue({
      user: { id: 7, username: "jdoe", suspended: 0 },
      created: false,
    });
    await ldapLogin(request, mockResponse(), {
      username: "jdoe",
      password: "pw",
    });
    expect(Workspace.new).not.toHaveBeenCalled();
  });

  it("still logs the user in when the workspace cannot be created", async () => {
    authenticate.mockResolvedValue({ externalId: "g", username: "jdoe" });
    Workspace.new.mockResolvedValue({ workspace: null, message: "boom" });
    User.upsertFromLdap.mockResolvedValue({
      user: { id: 7, username: "jdoe", suspended: 0 },
      created: true,
    });
    const response = mockResponse();
    await ldapLogin(request, response, { username: "jdoe", password: "pw" });
    expect(Workspace.new).toHaveBeenCalledWith("jdoe", 7);
    expect(response.json.mock.calls[0][0]).toMatchObject({ valid: true });
  });

  it("refuses suspended users", async () => {
    authenticate.mockResolvedValue({ externalId: "g", username: "jdoe" });
    User.upsertFromLdap.mockResolvedValue({
      user: { id: 7, username: "jdoe", suspended: 1 },
      created: false,
    });
    const response = mockResponse();

    await ldapLogin(request, response, { username: "jdoe", password: "pw" });
    expect(response.json.mock.calls[0][0]).toMatchObject({
      valid: false,
      token: null,
      message: "[004] Account suspended by admin.",
    });
  });

  it.each([
    [LDAP_ERROR_REASONS.invalidCredentials, 200, "[006]"],
    [LDAP_ERROR_REASONS.userNotFound, 200, "[006]"],
    [LDAP_ERROR_REASONS.ambiguousUser, 200, "[006]"],
    [LDAP_ERROR_REASONS.notInGroup, 200, "[007]"],
    [LDAP_ERROR_REASONS.linkRefused, 200, "[009]"],
    [LDAP_ERROR_REASONS.serverUnreachable, 503, "[008]"],
    [LDAP_ERROR_REASONS.misconfigured, 503, "[008]"],
  ])("maps %s to HTTP %i %s", async (reason, status, code) => {
    authenticate.mockRejectedValue(new LdapAuthError(reason, "detail"));
    const response = mockResponse();

    await ldapLogin(request, response, { username: "jdoe", password: "pw" });
    expect(response.status).toHaveBeenCalledWith(status);
    const body = response.json.mock.calls[0][0];
    expect(body).toMatchObject({ valid: false, token: null, user: null });
    expect(body.message.startsWith(code)).toBe(true);
    // Internal details are never sent to the client.
    expect(body.message).not.toContain("detail");
    expect(EventLogs.logEvent).toHaveBeenCalledWith("failed_login_ldap", {
      ip: "127.0.0.1",
      username: "jdoe",
      reason,
    });
  });

  it("treats unexpected errors as a directory failure", async () => {
    authenticate.mockRejectedValue(new Error("boom"));
    const response = mockResponse();
    await ldapLogin(request, response, { username: "jdoe", password: "pw" });
    expect(response.status).toHaveBeenCalledWith(503);
  });
});
