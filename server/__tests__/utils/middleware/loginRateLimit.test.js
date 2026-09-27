const {
  loginRateLimit,
  _resetLoginRateLimit,
} = require("../../../utils/middleware/loginRateLimit");

function attempt({ username = "jdoe", ip = "10.0.0.1", result } = {}) {
  const request = { ip, body: { username, password: "x" } };
  const response = { statusCode: result?.status || 200 };
  response.status = jest.fn((code) => {
    response.statusCode = code;
    return response;
  });
  response.json = jest.fn(() => response);
  const next = jest.fn(() => response.json(result?.body));
  loginRateLimit(request, response, next);
  return { response, next };
}

const failure = { body: { valid: false } };
const success = { body: { valid: true } };

describe("loginRateLimit", () => {
  const ORIGINAL_MAX = process.env.LOGIN_MAX_FAILED_ATTEMPTS;

  beforeEach(() => {
    _resetLoginRateLimit();
    process.env.LOGIN_MAX_FAILED_ATTEMPTS = "3";
  });
  afterAll(() => {
    if (ORIGINAL_MAX === undefined) delete process.env.LOGIN_MAX_FAILED_ATTEMPTS;
    else process.env.LOGIN_MAX_FAILED_ATTEMPTS = ORIGINAL_MAX;
  });

  it("blocks after too many failures for the same IP and username", () => {
    for (let i = 0; i < 3; i++) attempt({ result: failure });
    const { response, next } = attempt({ result: success });
    expect(next).not.toHaveBeenCalled();
    expect(response.status).toHaveBeenCalledWith(429);
  });

  it("tracks usernames case-insensitively and separately", () => {
    for (let i = 0; i < 3; i++)
      attempt({ username: i % 2 ? "JDoe" : "jdoe", result: failure });
    expect(attempt({ username: "JDOE" }).next).not.toHaveBeenCalled();
    expect(attempt({ username: "other" }).next).toHaveBeenCalled();
  });

  it("resets the counter after a successful login", () => {
    attempt({ result: failure });
    attempt({ result: failure });
    attempt({ result: success });
    attempt({ result: failure });
    attempt({ result: failure });
    expect(attempt({ result: success }).next).toHaveBeenCalled();
  });

  it("does not count server errors (eg: directory unavailable)", () => {
    const unavailable = { status: 503, body: { valid: false } };
    for (let i = 0; i < 5; i++) attempt({ result: unavailable });
    expect(attempt({ result: success }).next).toHaveBeenCalled();
  });
});
