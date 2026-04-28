const express = require('express')
const bcrypt = require('bcrypt')
const sqlite3 = require('sqlite3').verbose()
const session = require('express-session')

const app = express()
const db = new sqlite3.Database('users.db')

app.use(express.urlencoded({ extended: true }))
app.use(session({ secret: 'abc', resave: false, saveUninitialized: false }))

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    failed_attempts INTEGER DEFAULT 0,
    locked_until INTEGER DEFAULT 0
  )`)
})

app.get('/', (req, res) => {
  const msg = req.query.msg || ''
  res.send(`<!DOCTYPE html><html><head><title>Login</title>
    <style>body{font-family:Arial;max-width:400px;margin:60px auto;padding:20px}
    input{display:block;width:100%;padding:8px;margin:8px 0;box-sizing:border-box}
    button{padding:10px;background:#333;color:white;border:none;cursor:pointer;width:100%}
    .msg{color:red;font-weight:bold}.tabs a{margin-right:12px;text-decoration:none;color:#333;font-weight:bold}</style>
    </head><body>
    <div class="tabs">
      <a href="/?tab=login">Login</a>
      <a href="/?tab=register">Register</a>
    </div>
    <p class="msg">${msg}</p>
    ${req.query.tab === 'register' ? `
      <form method="POST" action="/register">
        <input name="username" placeholder="Username" required>
        <input name="password" type="password" placeholder="Password" required>
        <button>Register</button>
      </form>` : `
      <form method="POST" action="/login">
        <input name="username" placeholder="Username" required>
        <input name="password" type="password" placeholder="Password" required>
        <button>Login</button>
      </form>`}
    </body></html>`)
})

app.post('/register', async (req, res) => {
  const { username, password } = req.body
  const hashed = await bcrypt.hash(password, 10)
  db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashed], (err) => {
    if (err) return res.redirect('/?tab=register&msg=Username already exists')
    res.redirect('/?msg=Registered! Please login.')
  })
})

app.post('/login', async (req, res) => {
  const { username, password } = req.body
  const now = Date.now()

  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (!user) return res.status(401).send('Invalid username or password')

    // if locked, reject immediately
    if (user.locked_until && now < user.locked_until) {
      const secs = Math.ceil((user.locked_until - now) / 1000)
      const mins = Math.floor(secs / 60)
      const rem = secs % 60
      return res.status(403).send(`Account locked. Try again in ${mins}m ${rem}s`)
    }

    // lock expired — reset before checking password
    if (user.locked_until && now >= user.locked_until) {
      await new Promise(resolve =>
        db.run('UPDATE users SET failed_attempts = 0, locked_until = 0 WHERE username = ?', [username], resolve)
      )
      user.failed_attempts = 0
    }

    const match = await bcrypt.compare(password, user.password)

    if (!match) {
      const attempts = user.failed_attempts + 1

      // lock after 2 wrong attempts
      if (attempts >= 2) {
        const lockUntil = now + 5 * 60 * 1000
        await new Promise(resolve =>
          db.run('UPDATE users SET failed_attempts = ?, locked_until = ? WHERE username = ?', [attempts, lockUntil, username], resolve)
        )
        return res.status(403).send('Account locked for 5 minutes after 2 failed attempts.')
      }

      await new Promise(resolve =>
        db.run('UPDATE users SET failed_attempts = ? WHERE username = ?', [attempts, username], resolve)
      )
      return res.status(401).send(`Invalid username or password. 1 attempt left before lockout.`)
    }

    // correct password — reset counters
    await new Promise(resolve =>
      db.run('UPDATE users SET failed_attempts = 0, locked_until = 0 WHERE username = ?', [username], resolve)
    )
    req.session.user = username
    res.send(`<h2>Welcome, ${username}!</h2><a href="/logout">Logout</a>`)
  })
})

app.get('/logout', (req, res) => { req.session.destroy(); res.redirect('/') })

app.listen(3000, () => console.log('Running at http://localhost:3000'))
