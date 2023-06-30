const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
dotenv.config();

const app = express();

const isAuthenticated = (req, res, next) => {
  try {
    const user = jwt.verify(req.headers.token, process.env.JWT_SECRET) 
    req.user = user
    next();
  } catch (error) {
    res.send ({status: 'FAILED', message: 'Please login first' })
  }
}

const isAuthorized = (req, res, next) => {
  if(req.user.isAdmin) {
    return next();
  } 
  res.send ({status: 'FAILED', message: `You don't have access to this page` })
};

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('./public'))

app.set('view engine', 'ejs');

const User = mongoose.model('User', {
  firstName: String,
  lastName: String,
  email: String,
  password: String,
  isAdmin: Boolean,
})

app.get('/', (req, res) => {
  res.send({ status: 'SUCCESS', message: 'All good!'})
});

app.post('/signup', async (req, res) => {
  try {
    const { firstName, lastName, email, password, isAdmin } = req.body;

    const userInDB = await User.findOne({ email });
    if(userInDB) {
      return res.send({ status: 'FAILED', message: 'User already exists. Please sign in!' })
    }

    const encryptedPassword = await bcrypt.hash(password, 10)
    const newUser = { 
      firstName, 
      lastName, 
      email, 
      password: encryptedPassword, 
      isAdmin 
    }
    await User.create(newUser)

    const jwtToken = jwt.sign(newUser, process.env.JWT_SECRET, { expiresIn: 60 });

    res.send({ status: 'SUCCESS', message: 'User signed up successfully', jwtToken })
  } catch (error) {
    res.send({ status: 'FAILED', message: 'Failed to sign up user' })
  }
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const userInDB = await User.findOne({ email });
    if(!userInDB) {
      return res.send({ status: 'FAILED', message: 'Cannot find user. Please sign up!' })
    }

    const passwordMatched = await bcrypt.compare(password, userInDB.password);
    if(passwordMatched) {
      const jwtToken = jwt.sign(userInDB.toJSON(), process.env.JWT_SECRET, { expiresIn: 60 });

      res.send({ status: 'SUCCESS', message: 'User logged in successfully', jwtToken })
    } else {
      res.send({ status: 'FAILED', message: 'Invalid credentials' })
    }
  } catch (error) {
    res.send({ status: 'FAILED', message: 'Failed to sign in user' })
  }
});

app.get('/profile', isAuthenticated, async (req, res) => { 
  const fullName = req.user.firstName + ' ' + req.user.lastName
  res.send({ status: 'SUCCESS', message: 'Welcome user!', fullName});
});

app.get('/admin-panel', isAuthenticated, isAuthorized, async (req, res) => { 
  const fullName = req.user.firstName + ' ' + req.user.lastName
  res.send({ status: 'SUCCESS', message: 'Welcome admin!', fullName});
});

app.listen(process.env.PORT, () => {
  mongoose.connect(process.env.MONGODB_URL)
    .then(() => console.log(`Server running on http://localhost:${process.env.PORT}`))
    .catch(error => console.log(error));
})



























/*
  ## Authentication vs Authorization
  - Authentication: Verify user's identity (Who are you?)
  - Authorization: Checking the access of logged in user (What access do you have?)

  ## bcrypt - Encrypt the password
  ## JWT (JSON Web Token)
*/