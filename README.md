# 🔐 SSE MTech — Lab Assignment 1
### Secure Login Implementation with bcrypt, Rate Limiting & 2FA

> **Course:** Secure Software Engineering — MTech  
> **Student:** Kushagra Ojha | Roll No: CB.SC.P2CYS25029  
> **Department:** Computer Science & Engineering

---

## 📋 Overview

This project demonstrates a progressively hardened Node.js authentication system built across three parts — from basic secure password storage, to defending against automated attacks, to full Two-Factor Authentication.

| Part | Focus | Key Tech |
|------|-------|----------|
| Part 1 | Secure password hashing | `bcrypt`, `SQLite`, `express-session` |
| Part 2 | Attack simulation & defence | `Hydra`, Rate limiting, Account lockout |
| Part 3 | Two-Factor Authentication | `speakeasy`, `qrcode`, Google Authenticator |

---

## 🗂️ Project Structure

```
SSE/
├── p1/
│   └── server.js          # Part 1 — bcrypt login
├── p2/
│   └── server.js          # Part 2 — rate limiting & lockout
├── p3/
│   └── server (4).js      # Part 3 — TOTP 2FA
└── README.md
```

---

## 🚀 Getting Started

### Prerequisites

- Node.js v18+
- npm

### Install dependencies

```bash
npm install express bcrypt sqlite3 express-session speakeasy qrcode
```

### Run a part

```bash
# Part 1
node p1/server.js

# Part 2
node p2/server.js

# Part 3
node p3/server.js
```

Server runs at **http://localhost:3000**

---

## Part 1 — Secure Login with bcrypt

Passwords are hashed using `bcrypt` with a cost factor of **10** before being stored in SQLite. Plaintext passwords are never stored at any point.

```js
const hashed = await bcrypt.hash(password, 10)
db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashed])
```

**Key behaviours:**
- Every registration produces a unique hash due to bcrypt's built-in salt
- Hashes begin with `$2b$10$` confirming cost factor 10
- Password verification takes ~100 ms — slow enough to deter brute force

---

## Part 2 — Credential Stuffing Attack & Defence

### Attack Simulation

[Hydra](https://tryhackme.com/room/hydra) was used to simulate a credential stuffing attack against the Part 1 server using a custom wordlist (`password.txt`).

```bash
hydra -l admin \
  -P ~/Documents/sse/p1/passwords.txt \
  -s 3000 -f -V localhost http-post-form \
  "/login:username=^USER^&password=^PASS^:F=Invalid username or password"
```

**Result (before defences):** 2 valid passwords found — accounts compromised.

### Defences Implemented

**IP-based Rate Limiting** — max 10 requests per IP per minute:
```js
if (ipMap[ip].count > 10) {
  return res.status(429).send('Too many attempts. Try again in a minute.')
}
```

**Account Lockout** — locked for 5 minutes after 5 failed attempts:
```js
if (attempts >= 5) {
  const lockUntil = now + 5 * 60 * 1000
  db.run('UPDATE users SET failed_attempts = ?, locked_until = ? WHERE username = ?', ...)
}
```

**Result (after defences):** Hydra receives HTTP 401 errors — 0 valid passwords found.

---

## Part 3 — TOTP-Based Two-Factor Authentication

TOTP (RFC 6238) generates a 6-digit code every 30 seconds from a shared secret. Implemented using `speakeasy` with QR code support via `qrcode`.

### Flow

1. User logs in with username + password
2. Visit `/setup-2fa` → server generates a TOTP secret and displays a QR code
3. User scans QR code with **Google Authenticator**
4. User enters the 6-digit OTP at `/verify-2fa` — secret saved to DB on success
5. All future logins require the OTP in addition to the password

### Security Decisions

| Setting | Value | Reason |
|---------|-------|--------|
| `window` (login) | `0` | Strict — OTP valid only in current 30s window; blocks replay attacks |
| `window` (setup verify) | `1` | Slight tolerance for UX during initial setup |
| Secret storage | Server-side session | Never exposed to client until verified |

```js
const valid = speakeasy.totp.verify({
  secret: user.totp_secret,
  encoding: 'base32',
  token: otp,
  window: 0   // No replay — code valid for current 30s window only
})
```

---

## 🔒 Security Summary

| Threat | Mitigation |
|--------|-----------|
| Plaintext password storage | bcrypt hashing (cost 10) |
| Rainbow table attacks | bcrypt built-in per-user salt |
| Brute force / credential stuffing | IP rate limiting (10 req/min) + account lockout (5 attempts → 5 min lock) |
| Account takeover (password leaked) | TOTP 2FA — second factor required |
| OTP replay attacks | `window: 0` — each code usable once per 30s window |
| Session hijacking | Server-side sessions (express-session), secrets never in cookies |

---

## 📦 Dependencies

| Package | Purpose |
|---------|---------|
| `express` | Web server framework |
| `bcrypt` | Password hashing |
| `sqlite3` | Lightweight database |
| `express-session` | Server-side session management |
| `speakeasy` | TOTP secret generation and verification |
| `qrcode` | QR code generation for Google Authenticator |

---

## 📚 References

- [npm bcrypt](https://www.npmjs.com/package/bcrypt)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [npm speakeasy](https://www.npmjs.com/package/speakeasy)
- [rockyou.txt wordlist](https://github.com/dw0rsec/rockyou.txt)
- [TryHackMe — Hydra](https://tryhackme.com/room/hydra)

---

<p align="center">Made for SSE MTech Lab — Department of CSE</p>
