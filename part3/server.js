const express = require('express')
const bcrypt = require('bcrypt')
const sqlite3 = require('sqlite3').verbose()
const session = require('express-session')
const speakeasy = require('speakeasy')
const qrcode = require('qrcode')

const app = express()
const db = new sqlite3.Database('users.db')

app.use(express.urlencoded({ extended: true }))
app.use(session({ secret: 'abc', resave: false, saveUninitialized: false }))

db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password TEXT,
  totp_secret TEXT,
  failed_attempts INTEGER DEFAULT 0,
  locked_until INTEGER DEFAULT 0
)`)

const ipMap = {}

function rateLimit(req, res, next) {
  const ip = req.ip
  const now = Date.now()

  if (!ipMap[ip] || now > ipMap[ip].reset) {
    ipMap[ip] = { count: 1, reset: now + 60 * 1000 }
    return next()
  }

  ipMap[ip].count++

  if (ipMap[ip].count > 10) {
    return res.status(429).send('Too many attempts. Try again in a minute.')
  }

  next()
}

function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect('/')
  next()
}

app.get('/', (req, res) => {
  const msg = req.query.msg || ''
  res.send(`
    <!DOCTYPE html>
    <html>
    <head><title>Secure Login</title>
    <style>
      body { font-family: Arial; max-width: 420px; margin: 60px auto; padding: 20px; }
      input { display: block; width: 100%; padding: 8px; margin: 8px 0; box-sizing: border-box; }
      button { padding: 10px 20px; background: #333; color: white; border: none; cursor: pointer; width: 100%; }
      .msg { color: red; margin: 10px 0; }
      .tabs { display: flex; gap: 10px; margin-bottom: 20px; }
      .tabs a { text-decoration: none; color: #333; font-weight: bold; border-bottom: 2px solid transparent; padding-bottom: 4px; }
      .tabs a.active { border-color: #333; }
      small { color: #888; }
    </style>
    </head>
    <body>
      <div class="tabs">
        <a href="/?tab=login" class="${req.query.tab !== 'register' ? 'active' : ''}">Login</a>
        <a href="/?tab=register" class="${req.query.tab === 'register' ? 'active' : ''}">Register</a>
      </div>
      <p class="msg">${msg}</p>
      ${req.query.tab === 'register' ? `
        <form method="POST" action="/register">
          <input name="username" placeholder="Username" required>
          <input name="password" type="password" placeholder="Password" required>
          <button type="submit">Register</button>
        </form>
      ` : `
        <form method="POST" action="/login">
          <input name="username" placeholder="Username" required>
          <input name="password" type="password" placeholder="Password" required>
          <input name="otp" placeholder="2FA Code (leave blank if not set up)" maxlength="6">
          <small>Only needed after you set up 2FA</small><br><br>
          <button type="submit">Login</button>
        </form>
      `}
    </body>
    </html>
  `)
})

app.post('/register', async (req, res) => {
  const { username, password } = req.body
  const hashed = await bcrypt.hash(password, 10)
  db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashed], (err) => {
    if (err) return res.redirect('/?tab=register&msg=Username already exists')
    res.redirect('/?msg=Registered! Now login.')
  })
})

app.post('/login', rateLimit, (req, res) => {
  const { username, password, otp } = req.body
  const now = Date.now()

  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (!user) return res.redirect('/?msg=Invalid username or password')

    if (user.locked_until && now < user.locked_until) {
      const secsLeft = Math.ceil((user.locked_until - now) / 1000)
      return res.redirect(`/?msg=Account locked. Wait ${secsLeft} seconds.`)
    }

    const match = await bcrypt.compare(password, user.password)

    if (!match) {
      const attempts = user.failed_attempts + 1
      if (attempts >= 5) {
        const lockUntil = now + 5 * 60 * 1000
        db.run('UPDATE users SET failed_attempts = ?, locked_until = ? WHERE username = ?', [attempts, lockUntil, username])
        return res.redirect('/?msg=Account locked for 5 minutes.')
      }
      db.run('UPDATE users SET failed_attempts = ? WHERE username = ?', [attempts, username])
      return res.redirect(`/?msg=Wrong password. ${5 - attempts} attempts left.`)
    }

    // password correct — check 2FA if user has it set up
    if (user.totp_secret) {
      if (!otp) return res.redirect('/?msg=Please enter your 2FA code')

      const valid = speakeasy.totp.verify({
        secret: user.totp_secret,
        encoding: 'base32',
        token: otp,
        window: 0   // window: 0 means no replay — code valid for current 30s window only
      })

      if (!valid) return res.redirect('/?msg=Invalid or expired 2FA code')
    }

    db.run('UPDATE users SET failed_attempts = 0, locked_until = 0 WHERE username = ?', [username])
    req.session.user = username
    res.redirect('/dashboard')
  })
})

app.get('/dashboard', requireLogin, (req, res) => {
  res.send(`
    <h2>Welcome, ${req.session.user}!</h2>
    <a href="/setup-2fa">Setup / Reset 2FA</a> &nbsp;|&nbsp; <a href="/logout">Logout</a>
  `)
})

app.get('/setup-2fa', requireLogin, (req, res) => {
  const secret = speakeasy.generateSecret({
    name: `SecureApp:${req.session.user}`
  })

  // temporarily store secret in session until user verifies
  req.session.pending_secret = secret.base32

  qrcode.toDataURL(secret.otpauth_url, (err, qr) => {
    res.send(`
      <h2>Set Up Two-Factor Authentication</h2>
      <p>Scan this QR code with <b>Google Authenticator</b>:</p>
      <img src="${qr}"><br><br>
      <p>Or enter this key manually: <code>${secret.base32}</code></p>
      <p>Then verify your setup by entering the 6-digit code:</p>
      <form method="POST" action="/verify-2fa">
        <input name="otp" placeholder="6-digit code" maxlength="6" required>
        <button type="submit">Verify & Enable 2FA</button>
      </form>
    `)
  })
})

app.post('/verify-2fa', requireLogin, (req, res) => {
  const { otp } = req.body
  const secret = req.session.pending_secret

  if (!secret) return res.redirect('/setup-2fa')

  const valid = speakeasy.totp.verify({
    secret,
    encoding: 'base32',
    token: otp,
    window: 1
  })

  if (!valid) return res.send('Wrong code. <a href="/setup-2fa">Try again</a>')

  db.run('UPDATE users SET totp_secret = ? WHERE username = ?', [secret, req.session.user], () => {
    delete req.session.pending_secret
    res.send('<h3>2FA enabled successfully!</h3><a href="/dashboard">Go to dashboard</a>')
  })
})

app.get('/logout', (req, res) => {
  req.session.destroy()
  res.redirect('/')
})

app.listen(3000, () => console.log('Part 3 running at http://localhost:3000'))
