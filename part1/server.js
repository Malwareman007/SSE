const express = require('express')
const bcrypt = require('bcrypt')
const sqlite3 = require('sqlite3').verbose()
const session = require('express-session')

const app = express()
const db = new sqlite3.Database('users.db')

app.use(express.urlencoded({ extended: true }))
app.use(session({ secret: 'abc', resave: false, saveUninitialized: false }))

db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password TEXT
)`)

app.get('/', (req, res) => {
  const msg = req.query.msg || ''
  res.send(`<!DOCTYPE html><html><head><title>Login</title>
    <style>body{font-family:Arial;max-width:400px;margin:60px auto;padding:20px}
    input{display:block;width:100%;padding:8px;margin:8px 0;box-sizing:border-box}
    button{padding:10px;background:#333;color:white;border:none;cursor:pointer;width:100%}
    .msg{color:red}.tabs a{margin-right:12px;text-decoration:none;color:#333;font-weight:bold}</style>
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
    res.redirect('/?tab=register&msg=Registered! Hash: ' + encodeURIComponent(hashed))
  })
})

app.post('/login', (req, res) => {
  const { username, password } = req.body
  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (!user) return res.redirect('/?msg=Invalid username or password')
    const match = await bcrypt.compare(password, user.password)
    if (!match) return res.redirect('/?msg=Invalid username or password')
    req.session.user = username
    res.send(`<h2>Welcome, ${username}!</h2><a href="/logout">Logout</a>`)
  })
})

app.get('/logout', (req, res) => { req.session.destroy(); res.redirect('/') })

app.listen(3000, () => console.log('Running at http://localhost:3000'))
