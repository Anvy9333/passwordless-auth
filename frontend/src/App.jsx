import { useEffect, useMemo, useState } from "react";
import Turnstile from "react-turnstile";
import { registerPasskey, loginPasskey } from "./webauthn";


export default function App() {
  const [health, setHealth] = useState(null);
  const [me, setMe] = useState(null);

  // login / register inputs
  const [username, setUsername] = useState("");
  const [loginUsername, setLoginUsername] = useState("");
  const [role, setRole] = useState("patient");

  // UI state
  const [msg, setMsg] = useState("");
  const [page, setPage] = useState("loading"); 

  // doctor 
  const [doctorData, setDoctorData] = useState(null);

  // Turnstile captcha
  const [captchaToken, setCaptchaToken] = useState(null);
  const [captchaKey, setCaptchaKey] = useState(0);

  const API = "https://localhost:4433";
  const UsernameRegex = /^[a-zA-Z0-9._-]{3,32}$/;
  
  const googleLinked = Boolean(me?.oidc?.google);


  function validateUsername(u) {
  if (!u || typeof u !== "string") return "Username required";
  if (!UsernameRegex.test(u)) return "Username must be 3-32 chars (a-zA-Z0-9._-)";
  return null;
}

  function resetCaptcha() {
    setCaptchaToken(null);
    setCaptchaKey((k) => k + 1); // force widget remount
  }

  async function refreshMeOnce() {
    try {
      const r = await fetch("/api/me", { credentials: "include" });
      if (!r.ok) return null;
      return await r.json();
    } catch {
      return null;
    }
  }

  async function refreshMeWithRetry({ tries = 6, delayMs = 150 } = {}) {
    for (let i = 0; i < tries; i++) {
      const session = await refreshMeOnce();
      if (session) return session;
      // small wait (cookie/session propagation, especially behind gateway)
      await new Promise((res) => setTimeout(res, delayMs));
    }
    return null;
  }

  // Initial load: health + session restore
  useEffect(() => {
    fetch("/api/health")
      .then((r) => r.json())
      .then(setHealth)
      .catch(() => setHealth({ ok: false }));

    (async () => {
      const session = await refreshMeWithRetry({ tries: 2, delayMs: 80 });
      setMe(session);
      setPage(session ? "main" : "login");
    })();
  }, []);

  async function handleCreateUser(e) {
    e.preventDefault();
    setMsg("");
    setDoctorData(null);
    const err = validateUsername(username);
      if (err) {
        setMsg(err); 
        return;
      }
    try {
      const r = await fetch("/api/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: username.trim(), role, captchaToken }),
      });
      const data = await r.json().catch(() => ({}));
      if (!r.ok) return setMsg(data.error || "Register failed");
      await registerPasskey();
      setMsg(`Created ${role} "${username.trim()}"`);
      setUsername("");
      resetCaptcha();
    } catch (err) {
      console.error(err);
      setMsg("Network error");
    }
  }

  
  async function handleLogin(e) {
    e.preventDefault();
    setMsg("");
    setDoctorData(null);

    const u = (loginUsername || "").trim();
    const err = validateUsername(u);
    if (err) {
      setMsg(err);
      return;
    }
    let loginErr = null;
    try {
      
      const res = await loginPasskey(u, captchaToken);
      if (res && res.ok === false) {
        loginErr = res.error || "Login failed";
      }
    } catch (err) {
      console.error(err);
      loginErr = err?.message || "Login failed";
    }

    const session = await refreshMeWithRetry({ tries: 2, delayMs: 250 });

    if (session) {
      setMe(session);
      setPage("main");
      setMsg("Logged in");
      resetCaptcha();
      return;
    }

    
    setMsg(loginErr || "Login failed");
  }

  async function logout() {
    setMsg("");
    setDoctorData(null);
    try {
      await fetch("/api/logout", { method: "POST", credentials: "include" });
    } catch {
      // ignore
    }
    setMe(null);
    setPage("login");
    setMsg("Logged out");
    resetCaptcha();
  }

  async function callDoctor() {
    setMsg("");
    setDoctorData(null);

    try {
      const r = await fetch(`${API}/api/doctor/hello`, {
        method: "GET",
        credentials: "include",
      });

      const data = await r.json().catch(() => ({}));
      if (!r.ok) {
        setMsg(data.error || `Doctor API error (status ${r.status})`);
        return;
      }
      setDoctorData(data);
      setMsg("Doctor API call OK");
    } catch (e) {
      console.error(e);
      setMsg(e?.message || "Network error");
    }
  }

  const styles = useMemo(
    () => ({
      page: {
        minHeight: "100vh",
        width: "100vw",
        padding: 28,
        boxSizing: "border-box",
        color: "#eaeaea",
        fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, sans-serif",
        background:
          "radial-gradient(1200px 600px at 20% 10%, rgba(88,101,242,0.25), transparent 55%), radial-gradient(900px 500px at 80% 20%, rgba(34,197,94,0.14), transparent 55%), #0b0e14",
      },
      shell: {
        width: "100%",
        display: "grid",
        gap: 16,
      },
      topbar: {
        width: "100%",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        gap: 12,
      },
      brand: { display: "flex", flexDirection: "column", gap: 2 },
      h1: { margin: 0, fontSize: 34, letterSpacing: 0.2 },
      muted: { margin: 0, color: "#aab2c0", fontSize: 13 },

      card: {
        background: "rgba(255,255,255,0.04)",
        border: "1px solid rgba(255,255,255,0.10)",
        borderRadius: 14,
        padding: 16,
        boxShadow: "0 12px 40px rgba(0,0,0,0.35)",
        width: "100%",
        boxSizing: "border-box",
      },

      gridAuto: {
        display: "grid",
        gap: 16,
        gridTemplateColumns: "repeat(auto-fit, minmax(420px, 1fr))",
        alignItems: "start",
        width: "100%",
      },

      sectionTitle: { margin: "0 0 10px", fontSize: 14, color: "#cfd6e4" },
      input: {
        width: "100%",
        background: "rgba(255,255,255,0.06)",
        border: "1px solid rgba(255,255,255,0.12)",
        color: "#eaeaea",
        borderRadius: 10,
        padding: "10px 12px",
        outline: "none",
        boxSizing: "border-box",
      },
      row: { display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" },
      button: {
        border: "1px solid rgba(255,255,255,0.16)",
        background: "rgba(255,255,255,0.07)",
        color: "#eaeaea",
        borderRadius: 10,
        padding: "10px 12px",
        cursor: "pointer",
      },
      buttonPrimary: {
        border: "1px solid rgba(88,101,242,0.55)",
        background: "rgba(88,101,242,0.18)",
      },
      buttonDanger: {
        border: "1px solid rgba(239,68,68,0.55)",
        background: "rgba(239,68,68,0.12)",
      },
      small: { fontSize: 12, color: "#aab2c0" },
      pre: {
        margin: 0,
        whiteSpace: "pre-wrap",
        wordBreak: "break-word",
        fontSize: 12,
        color: "#d9dee8",
        background: "rgba(0,0,0,0.25)",
        border: "1px solid rgba(255,255,255,0.08)",
        borderRadius: 12,
        padding: 12,
      },
      msg: {
        margin: 0,
        padding: "10px 12px",
        borderRadius: 12,
        background: "rgba(0,0,0,0.25)",
        border: "1px solid rgba(255,255,255,0.08)",
        color: "#eaeaea",
      },
      divider: {
        height: 1,
        background: "rgba(255,255,255,0.10)",
        margin: "12px 0",
      },
    }),
    []
  );

  const canSubmit = !!captchaToken;

  return (
    <div style={styles.page}>
      <div style={styles.shell}>
        <div style={styles.topbar}>
          <div style={styles.brand}>
            <h1 style={styles.h1}>Secure Hosto</h1>
            <p style={styles.muted}>
              {health ? `Health: ${health.ok ? "OK" : "DOWN"}` : "Health: ..."}
            </p>
          </div>

          {page === "main" && (
            <button
              onClick={logout}
              style={{ ...styles.button, ...styles.buttonDanger }}
            >
              Logout
            </button>
          )}
        </div>

        {msg && <p style={styles.msg}>{msg}</p>}

        {page === "loading" && (
          <div style={styles.card}>
            <p style={{ margin: 0 }}>Loading...</p>
          </div>
        )}

        {page === "login" && (
          <LoginPage
            styles={styles}
            role={role}
            setRole={setRole}
            username={username}
            setUsername={setUsername}
            loginUsername={loginUsername}
            setLoginUsername={setLoginUsername}
            handleCreateUser={handleCreateUser}
            handleLogin={handleLogin}
            canSubmit={canSubmit}
            captchaKey={captchaKey}
            setCaptchaToken={setCaptchaToken}
          />
        )}

        {page === "main" && (
          <MainPage
            styles={styles}
            me={me}
            doctorData={doctorData}
            callDoctor={callDoctor}
            captchaToken={captchaToken}
            resetCaptcha={resetCaptcha}
            setMsg={setMsg}
            googleLinked={googleLinked}
          />
        )}
      </div>
    </div>
  );
}

function LoginPage({
  styles,
  role,
  setRole,
  username,
  setUsername,
  loginUsername,
  setLoginUsername,
  handleCreateUser,
  handleLogin,
  canSubmit,
  captchaKey,
  setCaptchaToken,
}) {
  return (
    <div style={styles.gridAuto}>
      <div style={styles.card}>
        <h3 style={styles.sectionTitle}>Login</h3>

        <form onSubmit={handleLogin} style={{ display: "grid", gap: 10 }}>
          <input
            style={styles.input}
            placeholder="Username"
            value={loginUsername}
            onChange={(e) => setLoginUsername(e.target.value)}
          />

          <div style={styles.row}>
            <button
              type="submit"
              disabled={!canSubmit}
              style={{
                ...styles.button,
                ...styles.buttonPrimary,
                opacity: canSubmit ? 1 : 0.55,
                cursor: canSubmit ? "pointer" : "not-allowed",
              }}
            >
              Login
            </button>
            <button onClick={() => (window.location.href = "/api/oidc/start/google")}>
              Recover with Google
            </button>
          </div>

          <div style={styles.divider} />

          <div style={{ display: "grid", gap: 8 }}>
            <Turnstile
              key={captchaKey}
              sitekey={import.meta.env.VITE_TURNSTILE_SITE_KEY}
              onVerify={(token) => setCaptchaToken(token)}
              onExpire={() => setCaptchaToken(null)}
              onError={() => setCaptchaToken(null)}
            />
            <span style={styles.small}>
              {canSubmit ? "Captcha OK ✅" : "Please verify the captcha"}
            </span>
          </div>
        </form>
      </div>

      <div style={styles.card}>
        <h3 style={styles.sectionTitle}>Create user</h3>
        <form onSubmit={handleCreateUser} style={{ display: "grid", gap: 10 }}>
          <div style={styles.row}>
            <select
              value={role}
              onChange={(e) => setRole(e.target.value)}
              style={{ ...styles.input, width: 170 }}
            >
              <option value="patient">patient</option>
              <option value="doctor">doctor</option>
            </select>

            <input
              style={styles.input}
              placeholder="New username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
            />
          </div>

          <div style={styles.row}>
            <button
              type="submit"
              disabled={!canSubmit}
              style={{
                ...styles.button,
                ...styles.buttonPrimary,
                opacity: canSubmit ? 1 : 0.55,
                cursor: canSubmit ? "pointer" : "not-allowed",
              }}
            >
              Create user
            </button>
            <span style={styles.small}>
              Uses the same captcha token as login (simple but OK for your demo).
            </span>
          </div>
        </form>
      </div>
    </div>
  );
}

function MainPage({ styles, me, doctorData, callDoctor, captchaToken, resetCaptcha, setMsg, googleLinked }) {
  return (
    <div style={styles.card}>
      <h3 style={styles.sectionTitle}>Main page</h3>

      <p style={{ margin: "0 0 12px", color: "#cfd6e4" }}>
        You&apos;re logged in. This is the placeholder where your real app screens
        will go.
      </p>

      <div style={styles.gridAuto}>
        <div style={styles.card}>
          <h3 style={styles.sectionTitle}>Session</h3>
          <pre style={styles.pre}>{JSON.stringify(me, null, 2)}</pre>
        </div>

        <div style={styles.card}>
          <h3 style={styles.sectionTitle}>Actions</h3>
          <div style={{ marginTop: 12 }}>
          <button onClick={async () => {
              setMsg?.(""); 
              try {
                const res = await registerPasskey(captchaToken);
                if (res?.ok || res?.verified) {
                  resetCaptcha();
                  alert("Passkey added for this account ");
                } else {
                  alert(res?.error || "Passkey registration failed");
                }
              } catch (e) {
                console.error(e);
                alert("Passkey registration failed");
              }
            }}
            style={{ ...styles.button, ...styles.buttonPrimary }}
          >
            Add passkey (this device)
          </button>
          <div style={{ marginTop: "1rem" }}>
            {!googleLinked ? (
              <button
                onClick={() => {
                  window.location.href = "/api/oidc/link/google";
                }}
              >
                🔗 Link Google (recovery)
              </button>
            ) : (
              <div style={{ color: "#4caf50", fontWeight: "bold" }}>
                ✅ Google linked<br />
                <small>{me.oidc.google.email}</small>
              </div>
            )}
          </div>
        </div>

          {me?.role === "doctor" && (
            <>
              <div style={styles.row}>
                <button
                  onClick={callDoctor}
                  style={{ ...styles.button, ...styles.buttonPrimary }}
                >
                  Call /api/doctor/hello
                </button>
              </div>
              {doctorData && (
                <div style={{ marginTop: 10 }}>
                  <pre style={styles.pre}>
                    {JSON.stringify(doctorData, null, 2)}
                  </pre>
                </div>
              )}
              <p style={{ ...styles.small, marginTop: 10, maxWidth: 520 }}>
                Note: you must have imported your doctor certificate into your
                browser (from <code>doctor-*.p12</code>) for mTLS endpoints.
              </p>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
