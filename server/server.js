const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const dotenv = require('dotenv');

dotenv.config(); // Load environment variables from .env

const app = express();

// Use JSON middleware and CORS configuration
app.use(express.json());
app.use(cors({
  origin: 'http://localhost:3001',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  credentials: true, // Allow cookies and authentication headers
}));

app.use(cookieParser());

const saltRounds = 10;

// Connect to MongoDB Atlas with enhanced error handling and environment variables
mongoose.connect(
  process.env.MONGO_URI, // Use environment variables for sensitive data
  { useNewUrlParser: true, useUnifiedTopology: true }
)
  .then(() => console.log('Connected to MongoDB Atlas'))
  .catch((err) => {
    console.error('Error connecting to MongoDB Atlas:', err);
    process.exit(1);
  });

// Define user schema and model
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const User = mongoose.model('User', userSchema);
const verifyUser = (req, res, next) => {
  const token = req.cookies.token;
  if(!token){
    return res.json({error: "You are not authenticated"});
  } else {
    jwt.verify(token, "jwt-secret-key", (err, decoded) =>{
      if(err){
        return res.json({error: "Token is not valid"});
      } else{
        req.name = decoded.name;
        next();
      }
    })
  }
}
app.get('/check-auth', verifyUser, (req, res) => {
  return res.json({Status: "Success", name: req.name});
})

// Logout endpoint
app.post('/logout', (req, res) => {
  res.clearCookie('token', { httpOnly: true, sameSite: 'strict' }); // Clear the authentication cookie
  return res.json({ Status: 'Success', message: 'Logged out successfully' });
});


// Registration endpoint
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.json({ error: 'Missing name, email, or password' });
  }

  try {
    // Check if the email already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.json({ error: 'Email is already in use' });
    }

    const hashedPassword = await bcrypt.hash(password.toString(), saltRounds);
    const newUser = new User({
      name,
      email,
      password: hashedPassword,
    });

    await newUser.save();
    return res.json({ Status: 'Success' });
  } catch (error) {
    console.error('Error registering user:', error);
    return res.json({ error: 'Error registering user' });
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.json({ error: 'Missing email or password' });
  }

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.json({ error: 'Email not found' });
    }

    const isMatch = await bcrypt.compare(password.toString(), user.password);

    if (!isMatch) {
      return res.json({ error: 'Incorrect password' });
    }

    const token = jwt.sign({name: user.name}, "jwt-secret-key", {expiresIn: '1d',});

    // Set the token in a cookie
    res.cookie('token', token);

    return res.json({ Status: 'Success'});
  } catch (error) {
    console.error('Error logging in user:', error);
    return res.json({ error: 'Error logging in user' });
  }
});

// Start the server on port 8000
app.listen(8000, () => {
  console.log('Server running on port 8000');
});
