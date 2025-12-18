require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const User = require('./models/User');
const BlogPost = require('./models/BlogPost');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = 'uploads/';
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  }
});

const upload = multer({ 
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: (req, file, cb) => {
    const filetypes = /jpe?g|png|gif/;
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = filetypes.test(file.mimetype);
    
    if (extname && mimetype) {
      return cb(null, true);
    } else {
      cb(new Error('Only images are allowed (jpeg, jpg, png, gif)'));
    }
  }
});

// Initialize Express app
const app = express();

// Middleware
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use('/uploads', express.static('uploads'));

// Database connection
const MONGODB_URI = process.env.MONGODB_URI || process.env.MONGO_URL;
if (!MONGODB_URI) {
  console.error('❌ MongoDB URI not found in environment variables');
}

// Admin Model
const adminSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true, lowercase: true },
  password: { type: String, required: true, select: false },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  role: { type: String, enum: ['admin', 'editor'], default: 'admin' },
  lastLogin: Date,
  isActive: { type: Boolean, default: true }
}, { timestamps: true });

// Pre-save hook for password hashing
adminSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    console.log('🔐 Password hashed successfully');
    next();
  } catch (error) {
    console.error('❌ Error hashing password:', error);
    next(error);
  }
});

// Methods
adminSchema.methods.matchPassword = async function(enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

adminSchema.methods.getSignedJwtToken = function() {
  return jwt.sign(
    { id: this._id, role: this.role },
    process.env.JWT_SECRET || 'your_jwt_secret_key',
    { expiresIn: process.env.JWT_EXPIRE || '30d' }
  );
};

const Admin = mongoose.model('Admin', adminSchema);

// Root route
app.get('/', (req, res) => {
  res.json({
    message: 'Welcome to the Blog API',
    endpoints: {
      auth: {
        login: 'POST /api/blog/login',
        register: 'POST /api/blog/register',
        checkAuth: 'GET /api/blog/check-auth'
      },
      posts: {
        create: 'POST /api/blog/posts',
        list: 'GET /api/blog/posts',
        get: 'GET /api/blog/posts/:id',
        update: 'PUT /api/blog/posts/:id',
        delete: 'DELETE /api/blog/posts/:id'
      },
      users: {
        list: 'GET /api/blog/users',
        get: 'GET /api/blog/users/:id',
        update: 'PUT /api/blog/users/:id',
        delete: 'DELETE /api/blog/users/:id'
      }
    },
    status: 'running',
    timestamp: new Date().toISOString()
  });
});

// ==================== BLOG ROUTES ====================

// @desc    Get blog home
// @route   GET /api/blog
// @access  Public
app.get('/api/blog', async (req, res) => {
  try {
    const posts = await BlogPost.find({ status: 'published' })
      .sort({ createdAt: -1 })
      .limit(10);

    res.json({
      success: true,
      count: posts.length,
      data: posts
    });
  } catch (error) {
    console.error('Error fetching blog posts:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching blog posts'
    });
  }
});

// ==================== BLOG POST ROUTES ====================

// @desc    Create a new blog post
// @route   POST /api/blog/posts
// @access  Private
app.post('/api/blog/posts', upload.fields([
  { name: 'featuredImage', maxCount: 1 },
  { name: 'bannerImage', maxCount: 1 }
]), async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ success: false, message: 'Not authorized' });
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret_key');
    
    // Check if user is admin
    const user = await User.findById(decoded.id);
    if (!user || (user.role !== 'admin' && user.role !== 'editor')) {
      return res.status(403).json({ success: false, message: 'Not authorized to create posts' });
    }

    const { title, content, category, subcategory, authorName, status, tags, keywords } = req.body;
    
    // Process file uploads
    const featuredImage = req.files?.featuredImage?.[0];
    const bannerImage = req.files?.bannerImage?.[0];

    console.log('Files received:', { featuredImage, bannerImage });
    console.log('Request body:', req.body);

    // Create slug from title if not provided
    let slug = (req.body.slug || title || '').toLowerCase()
      .replace(/[^\w\s-]/g, '') // Remove special characters
      .replace(/\s+/g, '-') // Replace spaces with hyphens
      .replace(/--+/g, '-') // Replace multiple hyphens with single hyphen
      .replace(/^-+|-+$/g, ''); // Remove leading/trailing hyphens

    // Ensure slug is unique
    const existingPost = await BlogPost.findOne({ slug });
    if (existingPost) {
      slug = `${slug}-${Date.now()}`;
    }

    const postData = {
      title,
      slug,
      content,
      category,
      subcategory: subcategory || 'Article',
      authorName: authorName || user.name || 'Admin',
      status: status || 'draft',
      tags: Array.isArray(tags) ? tags : (tags ? [tags] : []),
      keywords: Array.isArray(keywords) ? keywords : (keywords ? [keywords] : []),
      author: user._id
    };

    // Add image URLs if files were uploaded
    if (featuredImage) {
      console.log('Processing featured image:', featuredImage);
      postData.featuredImage = {
        url: `/uploads/${featuredImage.filename}`,
        publicId: featuredImage.filename
      };
    }

    if (bannerImage) {
      console.log('Processing banner image:', bannerImage);
      postData.bannerImage = {
        url: `/uploads/${bannerImage.filename}`,
        publicId: bannerImage.filename
      };
    }

    const post = await BlogPost.create(postData);

    res.status(201).json({
      success: true,
      data: post
    });
  } catch (error) {
    console.error('Error creating blog post:', error);
    res.status(500).json({
      success: false,
      message: 'Error creating blog post',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// @desc    Update an existing blog post
// @route   PUT /api/blog/posts/:id
// @access  Private/Admin or Editor
app.put('/api/blog/posts/:id', upload.fields([
  { name: 'featuredImage', maxCount: 1 },
  { name: 'bannerImage', maxCount: 1 }
]), async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ success: false, message: 'Not authorized' });
    }

    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret_key');
    } catch (error) {
      return res.status(401).json({ success: false, message: 'Invalid token' });
    }

    const user = await User.findById(decoded.id);
    if (!user || (user.role !== 'admin' && user.role !== 'editor')) {
      return res.status(403).json({ success: false, message: 'Not authorized to update posts' });
    }

    const identifier = req.params.id;
    const isObjectId = mongoose.Types.ObjectId.isValid(identifier);
    let post = null;

    if (isObjectId) {
      post = await BlogPost.findById(identifier);
    }

    if (!post) {
      post = await BlogPost.findOne({ slug: identifier });
    }

    if (!post) {
      return res.status(404).json({ success: false, message: 'Blog post not found' });
    }

    const parseArrayField = (value, fallback = []) => {
      if (value === undefined || value === null || value === '') return fallback;
      if (Array.isArray(value)) return value;
      try {
        const parsed = JSON.parse(value);
        return Array.isArray(parsed) ? parsed : fallback;
      } catch (error) {
        return typeof value === 'string'
          ? value.split(',').map((item) => item.trim()).filter(Boolean)
          : fallback;
      }
    };

    const { title, content, category, subcategory, authorName, status } = req.body;

    if (title) {
      post.title = title;
    }
    if (content) {
      post.content = content;
    }
    if (category) {
      post.category = category;
    }
    if (subcategory) {
      post.subcategory = subcategory;
    }
    if (authorName) {
      post.authorName = authorName;
    }
    if (status) {
      post.status = status;
    }

    const incomingSlug = req.body.slug;
    if (incomingSlug && incomingSlug !== post.slug) {
      let newSlug = incomingSlug
        .toLowerCase()
        .replace(/[^\w\s-]/g, '')
        .replace(/\s+/g, '-')
        .replace(/--+/g, '-')
        .replace(/^-+|-+$/g, '');

      const slugExists = await BlogPost.findOne({ slug: newSlug, _id: { $ne: post._id } });
      if (slugExists) {
        newSlug = `${newSlug}-${Date.now()}`;
      }
      post.slug = newSlug;
    } else if (!incomingSlug && title) {
      let generatedSlug = title
        .toLowerCase()
        .replace(/[^\w\s-]/g, '')
        .replace(/\s+/g, '-')
        .replace(/--+/g, '-')
        .replace(/^-+|-+$/g, '');

      if (generatedSlug && generatedSlug !== post.slug) {
        const slugExists = await BlogPost.findOne({ slug: generatedSlug, _id: { $ne: post._id } });
        if (slugExists) {
          generatedSlug = `${generatedSlug}-${Date.now()}`;
        }
        post.slug = generatedSlug;
      }
    }

    post.tags = parseArrayField(req.body.tags, post.tags);
    post.keywords = parseArrayField(req.body.keywords, post.keywords);

    const featuredImage = req.files?.featuredImage?.[0];
    const bannerImage = req.files?.bannerImage?.[0];

    if (featuredImage) {
      post.featuredImage = {
        url: `/uploads/${featuredImage.filename}`,
        publicId: featuredImage.filename
      };
    }

    if (bannerImage) {
      post.bannerImage = {
        url: `/uploads/${bannerImage.filename}`,
        publicId: bannerImage.filename
      };
    }

    await post.save();

    res.json({
      success: true,
      data: post
    });
  } catch (error) {
    console.error('Error updating blog post:', error);
    res.status(500).json({
      success: false,
      message: 'Error updating blog post',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// @desc    Get all blog posts
// @route   GET /api/blog/posts
// @access  Public
// DELETE blog post
app.delete('/api/blog/posts/:id', async (req, res) => {
  try {
    // Get token from header
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ success: false, message: 'No token, authorization denied' });
    }

    // Verify token
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret');
    } catch (err) {
      return res.status(401).json({ success: false, message: 'Token is not valid' });
    }

    // Check if user is admin or author of the post
    const post = await BlogPost.findById(req.params.id);
    if (!post) {
      return res.status(404).json({ success: false, message: 'Blog post not found' });
    }

    // Check if user is admin or the author of the post
    if (decoded.role !== 'admin' && post.author.toString() !== decoded.id) {
      return res.status(403).json({ 
        success: false, 
        message: 'Not authorized to delete this post' 
      });
    }

    // Delete the post
    await BlogPost.findByIdAndDelete(req.params.id);
    
    res.json({ success: true, message: 'Blog post deleted successfully' });
  } catch (error) {
    console.error('Error deleting blog post:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// GET all blog posts with pagination and filtering
app.get('/api/blog/posts', async (req, res) => {
  try {
    const { status, category, author, page = 1, limit = 10 } = req.query;
    const query = {};

    if (status) query.status = status;
    if (category) query.category = category;
    if (author) query.author = author;

    const posts = await BlogPost.find(query)
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .exec();

    const count = await BlogPost.countDocuments(query);

    res.status(200).json({
      success: true,
      data: posts,
      totalPages: Math.ceil(count / limit),
      currentPage: page,
      totalPosts: count
    });
  } catch (error) {
    console.error('Error fetching blog posts:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching blog posts'
    });
  }
});

// ==================== AUTH ROUTES ====================

// @desc    Get all users
// @route   GET /api/blog/users
// @access  Private/Admin
app.get('/api/blog/users', async (req, res) => {
  try {
    console.log('Authorization header:', req.headers.authorization);
    
    // Get token from header
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      // Get token from header
      token = req.headers.authorization.split(' ')[1];
    } else if (req.cookies && req.cookies.token) {
      // Get token from cookie
      token = req.cookies.token;
    }

    if (!token) {
      console.error('No token provided');
      return res.status(401).json({
        success: false,
        message: 'Not authorized to access this route - No token provided'
      });
    }

    // Verify token
    console.log('Verifying token:', token.substring(0, 20) + '...');
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret_key');
    console.log('Token verified successfully for user ID:', decoded.id);
    
    // Check if user is admin in either User or Admin collection
    let user = await User.findById(decoded.id);
    let isAdmin = false;
    
    if (user) {
      isAdmin = user.role === 'admin';
    } else {
      // Check Admin collection if not found in User collection
      const adminUser = await Admin.findById(decoded.id);
      if (adminUser) {
        user = adminUser;
        isAdmin = true;
      }
    }
    
    if (!user || !isAdmin) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to access this route - Admin privileges required'
      });
    }

    // Get all users (excluding password)
    const users = await User.find({}).select('-password');
    
    res.status(200).json({
      success: true,
      count: users.length,
      data: users
    });
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error',
      error: error.message
    });
  }
});

// @desc    Update a user
// @route   PUT /api/blog/users/:id
// @access  Private/Admin
app.put('/api/blog/users/:id', async (req, res) => {
  try {
    // Get token from header
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Not authorized to access this route'
      });
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret_key');
    
    // Check if user is admin in either User or Admin collection
    let currentUser = await User.findById(decoded.id);
    let isAdmin = false;
    
    if (currentUser) {
      isAdmin = currentUser.role === 'admin';
    } else {
      // Check Admin collection if not found in User collection
      const adminUser = await Admin.findById(decoded.id);
      if (adminUser) {
        currentUser = adminUser;
        isAdmin = true;
      }
    }
    
    if (!currentUser || !isAdmin) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to update users - Admin privileges required'
      });
    }

    // Find the user to update
    let user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Update user fields
    const { name, username, email, role, status } = req.body;
    
    if (name) user.name = name;
    if (username) user.username = username;
    if (email) user.email = email;
    if (role) user.role = role;
    if (status) user.status = status;

    // Save updated user
    const updatedUser = await user.save();
    
    // Remove password from response
    updatedUser.password = undefined;

    res.status(200).json({
      success: true,
      data: updatedUser
    });

  } catch (error) {
    console.error('Update user error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error',
      error: error.message
    });
  }
});

// @desc    Delete a user
// @route   DELETE /api/blog/users/:id
// @access  Private/Admin
app.delete('/api/blog/users/:id', async (req, res) => {
  try {
    // Get token from header
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Not authorized to access this route'
      });
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret_key');
    
    // Check if user is admin in either User or Admin collection
    let user = await User.findById(decoded.id);
    let isAdmin = false;
    
    if (user) {
      isAdmin = user.role === 'admin';
    } else {
      // Check Admin collection if not found in User collection
      const adminUser = await Admin.findById(decoded.id);
      if (adminUser) {
        user = adminUser;
        isAdmin = true;
      }
    }
    
    if (!user || !isAdmin) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to access this route - Admin privileges required'
      });
    }

    // Don't allow deleting self
    if (decoded.id === req.params.id) {
      return res.status(400).json({
        success: false,
        message: 'You cannot delete your own account'
      });
    }

    const deletedUser = await User.findByIdAndDelete(req.params.id);
    
    if (!deletedUser) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    res.status(200).json({
      success: true,
      message: 'User deleted successfully',
      data: { id: deletedUser._id }
    });
  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error',
      error: error.message
    });
  }
});

// @desc    Register a new user
// @route   POST /api/blog/register
// @access  Public
app.post('/api/blog/register', async (req, res) => {
  try {
    const { name, email, password, role = 'user' } = req.body;

    // Validate input
    if (!name || !email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Please provide name, email, and password'
      });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ 
      $or: [
        { email: email.toLowerCase() },
        { username: name.toLowerCase() }
      ]
    });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'User with this email or username already exists'
      });
    }

    // Create new user (password will be hashed by pre-save hook)
    const user = new User({
      username: name.toLowerCase(),
      email: email.toLowerCase(),
      password,
      role,
      status: 'Active'
    });

    await user.save();

    // Generate token
    const token = user.getSignedJwtToken();

    res.status(201).json({
      success: true,
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        status: user.status
      }
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during registration',
      error: error.message
    });
  }
});

// @desc    Login user
// @route   GET /api/blog/login
// @access  Public
app.get('/api/blog/login', (req, res) => {
  return res.status(400).json({
    success: false,
    message: 'Please use POST method with username and password to login'
  });
});

// @route   POST /api/blog/login
// @access  Public
app.post('/api/blog/login', async (req, res) => {
  try {
    console.log('Login attempt with data:', { username: req.body.username });
    const { username, password } = req.body;

    // Validate input
    if (!username || !password) {
      console.log('Missing username or password');
      return res.status(400).json({
        success: false,
        message: 'Please provide username/email and password'
      });
    }

    try {
      // Check if login is using email (contains @) or username
      const isEmail = username.includes('@');
      let query = isEmail 
        ? { email: username.toLowerCase() }
        : { username: username.toLowerCase() };

      console.log('Searching for user with query:', JSON.stringify(query));
      
      // Find user
      const user = await User.findOne(query).select('+password');
      console.log('User found:', user ? 'Yes' : 'No');

      if (!user) {
        console.log('No user found with these credentials');
        return res.status(401).json({
          success: false,
          message: 'Invalid credentials'
        });
      }

      // Check if password matches
      console.log('Checking password...');
      
      // Check if matchPassword method exists
      if (typeof user.matchPassword !== 'function') {
        console.error('Error: matchPassword is not a function on user object');
        console.log('User object structure:', Object.keys(user));
        return res.status(500).json({
          success: false,
          message: 'Server configuration error',
          error: 'Authentication method not available'
        });
      }
      
      try {
        const isMatch = await user.matchPassword(password);
        
        if (!isMatch) {
          console.log('Password does not match');
          return res.status(401).json({
            success: false,
            message: 'Invalid credentials'
          });
        }
      } catch (error) {
        console.error('Password verification error:', error);
        throw error; // This will be caught by the outer catch block
      }

      // Create token
      console.log('Password matched, generating token...');
      const token = user.getSignedJwtToken();
      
      // Update last login
      user.lastLogin = Date.now();
      await user.save();
      console.log('User last login updated');

      // Return token and user info (without password)
      const userResponse = {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        status: user.status
      };

      console.log('Login successful for user:', userResponse.username);
      
      res.status(200).json({
        success: true,
        token,
        user: userResponse
      });

    } catch (dbError) {
      console.error('Database error during login:', dbError);
      throw dbError; // This will be caught by the outer catch block
    }

  } catch (error) {
    console.error('Login error details:', {
      message: error.message,
      stack: error.stack,
      name: error.name
    });
    
    res.status(500).json({
      success: false,
      message: 'Server error during login',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error',
      ...(process.env.NODE_ENV === 'development' && { stack: error.stack })
    });
  }
});

// ==================================================

// Server config
const PORT = 5000;


// Function to create/update admin
async function createOrUpdateAdmin(username, password, email, role = 'admin') {
  try {
    const existingAdmin = await Admin.findOne({ username });
    if (existingAdmin) {
      console.log(`ℹ️ Admin '${username}' exists. Updating password if needed...`);
      if (!existingAdmin.password.startsWith('$2a$') && !existingAdmin.password.startsWith('$2b$')) {
        existingAdmin.password = password;
        await existingAdmin.save();
        console.log(`✅ Updated password for admin '${username}'`);
      }
      return;
    }

    const admin = new Admin({ username, password, email: email || `${username}@example.com`, role });
    await admin.save();
    console.log(`✅ Created new admin '${username}'`);
  } catch (error) {
    console.error(`❌ Error creating/updating admin '${username}':`, error.message);
  }
}

// Start server
const startServer = async () => {
  try {
    console.log('🔌 Attempting to connect to MongoDB...');
    console.log('🔗 Connection string:', MONGODB_URI);
    
    try {
      await mongoose.connect(MONGODB_URI, { 
        useNewUrlParser: true, 
        useUnifiedTopology: true,
        serverSelectionTimeoutMS: 5000, // 5 seconds timeout
        socketTimeoutMS: 45000, // 45 seconds socket timeout
      });
      console.log('✅ Connected to MongoDB');
    } catch (dbError) {
      console.error('❌ MongoDB connection error:', dbError.message);
      console.log('💡 Make sure MongoDB is running locally. You can install it from: https://www.mongodb.com/try/download/community');
      console.log('💡 Or update the MONGODB_URI in the .env file to use a remote MongoDB instance');
      process.exit(1);
    }

    // Remove unhashed passwords
    const unhashedAdmins = await Admin.find({
      $or: [
        { password: { $not: { $regex: '^\$2[ab]\$' } } },
        { password: { $exists: false } }
      ]
    });
    if (unhashedAdmins.length > 0) {
      console.log('⚠️ Cleaning up unhashed passwords...');
      await Admin.deleteMany({ _id: { $in: unhashedAdmins.map(a => a._id) } });
      console.log('✅ Cleaned up unhashed admin accounts');
    }

    // Default admins
    await createOrUpdateAdmin(
      process.env.BLOG_ADMIN_USERNAME || 'blog',
      process.env.BLOG_ADMIN_PASSWORD || 'blog123',
      process.env.BLOG_ADMIN_EMAIL || 'blog@example.com'
    );
    await createOrUpdateAdmin('riddhi', 'riddhi123', 'riddhi@example.com');

    const server = app.listen(PORT, '0.0.0.0', () => {
      console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
      console.log(`🚀 Blog server running on port ${PORT}`);
      console.log(`🌐 API Base URL: http://localhost:${PORT}/api/blog`);
      console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    });

    // Handle server errors safely
    server.on('error', (err) => {
      if (err.code === 'EADDRINUSE') {
        console.error(`❌ Port ${PORT} is already in use. Please free it and restart.`);
      } else {
        console.error('❌ Server error:', err);
      }
    });

  } catch (error) {
    console.error('❌ Failed to start blog server:', error.message);
    console.error('💡 Terminal will stay open for debugging.');
  }
};

// Catch unhandled promise rejections
process.on('unhandledRejection', (err) => {
  console.error('❌ Unhandled Rejection:', err.message);
});

// Keep Node process alive so terminal doesn't close
process.stdin.resume();

// Start the server
startServer();