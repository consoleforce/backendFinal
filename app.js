const express = require('express');
const https = require('https');
const bodyParser = require('body-parser');
const session = require('express-session');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const path = require('path');
const winston = require('winston');
const morgan = require('morgan');
const helmet = require('helmet');
const fs = require('fs');


const app = express();
const port = 3000;
const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'registration1',
  password: 'qwerty123',
  port: 5432,
});

const logger = winston.createLogger({
  transports: [
    new winston.transports.Console({ level: 'info' }),
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log', level: 'info' }),
  ],
});

app.use(morgan('combined'));
app.use(helmet()); 
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({ secret: '123', resave: false, saveUninitialized: false }));
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

function isAuthenticated(req, res, next) {
  if (req.session.user) {
    return next();
  }
  res.redirect('/login');
}

function authorizeRole(allowedRoles) {
  return (req, res, next) => {
    const userRole = req.session.user ? req.session.user.role : null;

    if (allowedRoles.includes(userRole)) {
      return next();
    }

    res.status(403).send('Access Forbidden: You do not have permission to access this resource.');
  };Array
}
app.use((req, res, next) => {
  if (process.env.NODE_ENV === 'production' && req.headers['x-forwarded-proto'] !== 'https') {
    return res.redirect('https://' + req.headers.host + req.url);
  }
  next();
});

const httpsOptions = {
  key: fs.readFileSync('cert/privateKey.key'),
  cert: fs.readFileSync('cert/certificate.crt'),
};

app.get('/', async(req, res) => { res.sendFile(path.join(__dirname, 'public/html', 'home.html')); });

app.get('/registration', async(req, res) => { res.sendFile(path.join(__dirname, 'public/html', 'registration.html')); });

app.get('/logout', async(req, res) => { res.sendFile(path.join(__dirname, 'public/html', 'login.html')); });

app.post('/registration', async (req, res) => {
  const { username, email, password, role } = req.body;
  const existingUser = await pool.query('SELECT * FROM user1 WHERE username = $1', [username]);
  if (existingUser.rows.length > 0) {
    return res.send('Username already exists. Please choose a different username.');
  }
  const hashedPassword = await bcrypt.hash(password, 10);
  const result = await pool.query('INSERT INTO user1 (username, email, password, role) VALUES ($1, $2, $3, $4)', [username, email, hashedPassword, role]);
  logger.info(`${username} registered at ${new Date().toISOString()}`);
  res.redirect('/login');
});


app.get('/login', async(req, res) => { res.sendFile(path.join(__dirname, 'public/html', 'login.html')); });

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const result = await pool.query('SELECT * FROM user1 WHERE username = $1', [username]);
  if (result.rows.length > 0) {
    const user = result.rows[0];
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (isPasswordValid) {
      logger.info(`${username} logged in at ${new Date().toISOString()}`);
      req.session.user = user;
      res.redirect(`/${user.role}`);
    } else {
      res.send('Incorrect password. Please try again.');
    }
  } else {
    res.send('Username not found. Please check your username or register.');
  }
});


app.get('/admin', isAuthenticated, authorizeRole(['admin']), async (req, res) => {
  try {
    const resultBooks = await pool.query('SELECT * FROM books');
    const books = resultBooks.rows;
    const resultUsers = await pool.query('SELECT * FROM user1');
    const users = resultUsers.rows;
    res.render('admin', { user: req.session.user, books, users });
  } catch (error) {
    console.error('Error retrieving data:', error);
    res.status(500).send('Internal Server Error');
  }
});

app.post('/admin/update-role', isAuthenticated, authorizeRole(['admin']), async (req, res) => {
  const { userId, role } = req.body;
  
  try {
    await pool.query('UPDATE user1 SET role = $1 WHERE id = $2', [role, userId]);
    logger.info(`Admin updated role for user with ID ${userId} to ${role} at ${new Date().toISOString()}`);  
    res.redirect('/admin');
  } catch (error) {
    console.error('Error updating user role:', error);
    logger.error(`Error updating role for user with ID ${userId}: ${error.message}`);
    res.status(500).send('Internal Server Error');
  }
});


app.post('/admin/delete-user', isAuthenticated, authorizeRole(['admin']), async (req, res) => {
  const { userId } = req.body;

  try {
    await pool.query('DELETE FROM loans WHERE user_id = $1', [userId]);
    await pool.query('DELETE FROM user1 WHERE id = $1', [userId]);
    logger.info(`Admin deleted user with ID ${userId} at ${new Date().toISOString()}`); 
    res.redirect('/admin');
  } catch (error) {
    console.error('Error deleting user:', error);
    logger.error(`Error deleting user with ID ${userId}: ${error.message}`);
    res.status(500).send('Internal Server Error');
  }
});

app.post('/admin/user/:userId/description', isAuthenticated, authorizeRole(['admin']), async (req, res) => {
  const userId = req.params.userId;
  const { description } = req.body;

  try {
    await pool.query('UPDATE user1 SET description = $1 WHERE id = $2', [description, userId]);
    logger.info(`Admin updated description for user with ID ${userId} at ${new Date().toISOString()}`);
    res.redirect('/admin');
  } catch (error) {
    console.error('Error updating user description:', error);
    logger.error(`Error updating description for user with ID ${userId}: ${error.message}`);
    res.status(500).send('Internal Server Error');
  }
});

app.get('/moderator', isAuthenticated, authorizeRole(['admin', 'moderator']), async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM user1');
    const users = result.rows;
    res.render('moderator', { user: req.session.user, users });
  } catch (error) {
    console.error('Error retrieving user list:', error);
    res.status(500).send('Internal Server Error');
  }
});

app.post('/moderator/ban-user', isAuthenticated, authorizeRole(['admin', 'moderator']), async (req, res) => {
  const { userId } = req.body;
  try {
    await pool.query('UPDATE user1 SET status = $1 WHERE id = $2', ['banned', userId]);
    logger.info(`Moderator banned user with ID ${userId} at ${new Date().toISOString()}`);
    res.redirect('/moderator');
  } catch (error) {
    console.error('Error banning user:', error);
    logger.error(`Error banning user with ID ${userId}: ${error.message}`);
    res.status(500).send('Internal Server Error');
  }
});

app.post('/moderator/unban-user', isAuthenticated, authorizeRole(['admin', 'moderator']), async (req, res) => {
  const { userId } = req.body;
  try {
    await pool.query('UPDATE user1 SET status = $1 WHERE id = $2', ['active', userId]);
    logger.info(`Moderator unbanned user with ID ${userId} at ${new Date().toISOString()}`);
    res.redirect('/moderator');
  } catch (error) {
    console.error('Error unbanning user:', error);
    logger.error(`Error unbanning user with ID ${userId}: ${error.message}`);
    res.status(500).send('Internal Server Error');
  }
});


app.get('/user', isAuthenticated, async (req, res) => {
  const userId = req.session.user.id;
  try {
    const result = await pool.query('SELECT books.title, books.author, books.genre, loans.borrowed_date, loans.returned_date FROM loans JOIN books ON loans.book_id = books.id WHERE loans.user_id = $1', [userId]);
    const rentedBooks = result.rows;
    const userStatus = req.session.user ? req.session.user.status : null;
    const userDescription = req.session.user ? req.session.user.description : null;
    if (userStatus === 'banned') {
      req.session.destroy();
      return res.send('Your account has been banned.');
    }
    res.render('user', { user: req.session.user, description: userDescription, rentedBooks: rentedBooks });
  } catch (error) {
    console.error('Error fetching rented books:', error);
    res.status(500).send('Internal Server Error');
  }
});


app.get('/user/description', isAuthenticated, (req, res) => {
  res.render('user-description', { user: req.session.user });
});
app.post('/user/description', isAuthenticated, async (req, res) => {
  const { description } = req.body;
  const userId = req.session.user.id;
  try {
    await pool.query('UPDATE user1 SET description = $1 WHERE id = $2', [description, userId]);
    req.session.user.description = description;
    res.redirect('/user');
  } catch (error) {
    console.error('Error updating user description:', error);
    res.status(500).send('Internal Server Error');
  }
});

app.get('/user', isAuthenticated, (req, res) => {
  const userDescription = req.session.user ? req.session.user.description : null;
  res.render('user', { user: req.session.user, description: userDescription });
});
app.post('/user/settings', isAuthenticated, async (req, res) => {
  const userId = req.session.user.id;
  const { newUsername, newPassword } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE user1 SET username = $1, password = $2 WHERE id = $3', [newUsername, hashedPassword, userId]);
    req.session.user.username = newUsername;
    res.redirect('/user');
  } catch (error) {
    console.error('Error updating user settings:', error);
    res.status(500).send('Internal Server Error');
  }
});

app.use((err, req, res, next) => {
  logger.error(err.stack);
  res.status(500).send('Something went wrong!');
});


https.createServer(httpsOptions, app).listen(port, () => {
  logger.info(`Server is running at https://localhost:${port}`);
});