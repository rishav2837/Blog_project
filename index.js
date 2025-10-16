// SERVER

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const favicon = require('serve-favicon');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const mongoose = require('mongoose');
const validator = require('validator');
const fs = require('fs');

const jwtSecret = process.env.JWT_SECRET;
const app = express();
const PORT = process.env.PORT || 5500;

// ✅ Fixed favicon path (no "public" folder)
app.use(favicon(path.join(__dirname, 'favicon.ico')));

// MongoDB connection
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log("✅ MongoDB Connected");
  } catch (error) {
    console.error("❌ MongoDB Connection Error:", error.message);
  }
};

connectDB().then(() => {
  app.listen(PORT, () => {
    console.log(`🚀 Server listening on port ${PORT}`);
  });
});

// MongoDB Models
const Post = mongoose.model(
  'Post',
  new mongoose.Schema({
    title: String,
    content: String,
    imageUrl: String,
    author: String,
    timestamp: String,
  })
);

const User = mongoose.model(
  'User',
  new mongoose.Schema({
    username: String,
    password: String,
    role: String,
  })
);

// Middleware
app.use(cors({ origin: '*' }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname)));

// Serve main HTML file
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ✅ Fixed JWT Authentication Middleware
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).send({ error: 'Authorization header missing' });
  }

  const token = authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).send({ error: 'Token missing' });
  }

  jwt.verify(token, jwtSecret, (err, user) => {
    if (err) {
      console.error('JWT Verification Error', err.message);
      return res.status(403).send({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// User registration
app.post('/register', async (req, res) => {
  const { username, password, role } = req.body;

  const sanitizedUsername = validator.escape(username);
  const sanitizedPassword = validator.escape(password);

  if (!sanitizedUsername || !sanitizedPassword) {
    return res.status(400).send({ error: 'Invalid input data' });
  }

  const hashedPassword = await bcrypt.hash(sanitizedPassword, 10);

  const newUser = new User({
    username: sanitizedUsername,
    password: hashedPassword,
    role,
  });

  await newUser.save();
  res.status(201).send({ success: true });
});

// User login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  const sanitizedUsername = validator.escape(username);
  const sanitizedPassword = validator.escape(password);

  if (!sanitizedUsername || !sanitizedPassword) {
    return res.status(400).send({ error: 'Invalid input data' });
  }

  const user = await User.findOne({ username: sanitizedUsername });

  if (user) {
    // ✅ Fixed: Added await before bcrypt.compare()
    if (await bcrypt.compare(password, user.password)) {
      const accessToken = jwt.sign(
        { username: user.username, role: user.role },
        jwtSecret,
        { expiresIn: '24h' }
      );
      res.status(200).send({ success: true, token: accessToken, role: user.role });
    } else {
      res.status(401).send({ success: false, error: 'Invalid credentials' });
    }
  } else {
    res.status(401).send({ success: false, error: 'Invalid credentials' });
  }
});

// Read all posts
app.get('/posts', async (req, res) => {
  const posts = await Post.find();
  res.status(200).send(posts);
});

// Create new post (admin only)
app.post('/posts', authenticateJWT, async (req, res) => {
  if (req.user.role === 'admin') {
    const { title, content, imageUrl, author, timestamp } = req.body;

    const newPost = new Post({ title, content, imageUrl, author, timestamp });

    newPost
      .save()
      .then((savedPost) => res.status(201).send(savedPost))
      .catch(() => res.status(500).send({ error: 'Internal Server Error' }));
  } else {
    res.status(403).send({ error: 'Forbidden' });
  }
});

// Get individual post
app.get('/post/:id', async (req, res) => {
  const postId = req.params.id;
  const post = await Post.findById(postId);
  if (!post) return res.status(404).send('Post not found');

  fs.readFile(path.join(__dirname, 'post-detail.html'), 'utf8', (err, data) => {
    if (err) return res.status(500).send('Internal Server Error');

    const postDetailHtml = data
      .replace(/\${post.imageUrl}/g, post.imageUrl)
      .replace(/\${post.title}/g, post.title)
      .replace(/\${post.timestamp}/g, post.timestamp)
      .replace(/\${post.author}/g, post.author)
      .replace(/\${post.content}/g, post.content);

    res.status(200).send(postDetailHtml);
  });
});

// Delete post
app.delete('/posts/:id', authenticateJWT, async (req, res) => {
  if (req.user.role === 'admin') {
    try {
      await Post.findByIdAndDelete(req.params.id);
      res.status(200).send({ message: 'Post deleted' });
    } catch {
      res.status(500).send({ error: 'Internal Server Error' });
    }
  } else {
    res.status(403).send({ error: 'Forbidden' });
  }
});

// Update post
app.put('/posts/:id', authenticateJWT, async (req, res) => {
  const { title, content } = req.body;
  const postId = req.params.id;

  try {
    const post = await Post.findById(postId);
    if (!post) return res.status(404).send({ error: 'Post not found' });

    if (req.user.role === 'admin') {
      post.title = title;
      post.content = content;
      await post.save();
      res.status(200).send(post);
    } else {
      res.status(403).send({ error: 'Forbidden' });
    }
  } catch {
    res.status(500).send({ error: 'Internal Server Error' });
  }
});
