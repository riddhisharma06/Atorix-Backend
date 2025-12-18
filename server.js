const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bodyParser = require("body-parser");
const cookieParser = require('cookie-parser');
// Removing SendGrid import
const bcrypt = require("bcrypt"); // Add bcrypt for password hashing
require("dotenv").config();

const app = express();

// --- Environment Variable Checks (Good Practice) ---
// Remove SendGrid checks
if (!process.env.MONGODB_URI) {
  console.error(
    "ERROR: MONGODB_URI environment variable not set. Cannot connect to database."
  );
  process.exit(1); // Exit if DB connection string is missing
}

// --- CORS Configuration ---
const allowedOrigins = [
  "https://atorixit.com", // Main domain
  "https://www.atorixit.com", // Optional www subdomain
  "https://atorix-testing.vercel.app", // Testing domain
  "http://localhost:3000", // For local development
  "http://localhost:5000", // For local development alternative port
  "http://localhost:5001", // For local development alternative port
];

// Enable pre-flight requests for all routes
app.options('*', cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      console.warn(`CORS blocked request from origin: ${origin}`);
      callback(new Error("Not allowed by CORS"));
    }
  },
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true,
}));

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      console.warn(`CORS blocked request from origin: ${origin}`);
      callback(new Error("Not allowed by CORS"));
    }
  },
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true,
}));

// --- Middleware ---
app.use(bodyParser.json());
app.use(cookieParser());

// --- Database Connection ---
console.log('Attempting to connect to MongoDB...');
console.log('Connection string:', process.env.MONGODB_URI ? 'Found' : 'Missing');

// Simple MongoDB connection with error handling
async function connectDB() {
  try {
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('✅ MongoDB Connected Successfully!');
    console.log('Database Name:', mongoose.connection.name);
  } catch (err) {
    console.error('❌ MongoDB Connection Error:', err.message);
    console.error('Error name:', err.name);
    console.error('Error code:', err.code);
    process.exit(1);
  }
}

// Handle MongoDB connection events
mongoose.connection.on('error', err => {
  console.error('MongoDB connection error:', err);});

mongoose.connection.on('disconnected', () => {
  console.log('MongoDB disconnected');
});

// Connect to the database
connectDB();

// --- Mongoose Schema and Model ---
const userSchema = new mongoose.Schema({
  // Basic info (required)
  name: { type: String, required: [true, "Name is required"], trim: true },
  email: {
    type: String,
    required: [true, "Email is required"],
    trim: true,
    lowercase: true,
  },
  phone: {
    type: String,
    required: [true, "Phone number is required"],
    trim: true,
  },

  // Company info
  company: { type: String, trim: true },

  // Demo form specific fields
  role: { type: String, trim: true },
  interestedIn: { type: [String], default: [] },

  // Common fields
  message: { type: String, trim: true },
  createdAt: { type: Date, default: Date.now },
});

// Admin schema for storing admin login credentials
const adminSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true
  },
  password: {
    type: String,
    required: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

const User = mongoose.model("User", userSchema);
const Admin = mongoose.model("Admin", adminSchema);

// Initialize admin user if none exists
async function initializeAdmin() {
  try {
    const adminCount = await Admin.countDocuments();
    if (adminCount === 0) {
      const defaultUsername = 'admin@atorix.com';
      const defaultPassword = 'securePassword1234!';

      // Hash the default password
      const saltRounds = 10;
      const hashedPassword = await bcrypt.hash(defaultPassword, saltRounds);

      // Create new admin
      const newAdmin = new Admin({
        username: defaultUsername,
        password: hashedPassword
      });

      await newAdmin.save();
      console.log('Default admin user created.');
    }
  } catch (error) {
    console.error('Error initializing admin user:', error);
  }
}

// Call the initialization function
initializeAdmin();

// --- API Routes ---

// === Simple Ping Endpoint to Wake Up Server ===
app.get("/api/ping", (req, res) => {
  res
    .status(200)
    .json({
      status: "ok",
      message: "Server is awake",
      timestamp: new Date().toISOString(),
    });
});

// Import route files
const authRoutes = require('./routes/auth');
const blogRoutes = require('./routes/blog');

// Log all incoming requests for debugging
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.originalUrl}`);
  next();
});

// Mount routes with proper ordering
app.use('/api/blog', blogRoutes); // Mount blog routes at /api/blog
app.use('/api/auth', authRoutes);

// Handle preflight requests for all routes
app.options('*', (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.status(200).send();
});

// === Admin Authentication Route ===
app.post("/api/admin/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    // Basic validation
    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: "Username and password are required"
      });
    }

    // Find admin user
    const admin = await Admin.findOne({ username: username.toLowerCase() });

    // Check if admin exists
    if (!admin) {
      return res.status(401).json({
        success: false,
        message: "Invalid username or password"
      });
    }

    // Verify password
    const passwordMatch = await bcrypt.compare(password, admin.password);

    if (!passwordMatch) {
      return res.status(401).json({
        success: false,
        message: "Invalid username or password"
      });
    }

    // Generate a simple token (in a production app, you would use JWT)
    const token = `atorix_dashboard_${Date.now()}_${Buffer.from(username).toString('base64')}`;

    res.status(200).json({
      success: true,
      token,
      message: "Login successful"
    });
  } catch (error) {
    console.error("Error during admin login:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error"
    });
  }
});

// === Change Admin Password Route ===
app.post("/api/admin/change-password", async (req, res) => {
  try {
    const { username, currentPassword, newPassword } = req.body;

    // Basic validation
    if (!username || !currentPassword || !newPassword) {
      return res.status(400).json({
        success: false,
        message: "Username, current password, and new password are required"
      });
    }

    // Find admin user
    const admin = await Admin.findOne({ username: username.toLowerCase() });

    // Check if admin exists
    if (!admin) {
      return res.status(401).json({
        success: false,
        message: "Invalid username"
      });
    }

    // Verify current password
    const passwordMatch = await bcrypt.compare(currentPassword, admin.password);

    if (!passwordMatch) {
      return res.status(401).json({
        success: false,
        message: "Current password is incorrect"
      });
    }

    // Hash new password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

    // Update password
    admin.password = hashedPassword;
    await admin.save();

    res.status(200).json({
      success: true,
      message: "Password updated successfully"
    });
  } catch (error) {
    console.error("Error during password change:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error"
    });
  }
});

// === Form Submission Route ===
app.post("/api/submit", async (req, res) => {
  // Destructure inputs
  const {
    name: nameInput,
    email: emailInput,
    phone: phoneInput,
    company: companyInput,
    role: roleInput,
    interestedIn: interestedInInput,
    message: messageInput,
  } = req.body;

  // Trim values or use default if null/undefined
  const name = nameInput?.trim();
  const email = emailInput?.trim().toLowerCase();
  const phone = phoneInput?.trim();
  const company = companyInput?.trim() || "";
  const role = roleInput?.trim() || "";
  // interestedIn should be an array of strings; ensure it is
  let interestedIn = [];
  if (Array.isArray(interestedInInput)) {
    interestedIn = interestedInInput
      .map((item) => item.trim())
      .filter((item) => item.length > 0);
  } else if (
    typeof interestedInInput === "string" &&
    interestedInInput.trim().length > 0
  ) {
    // If a single string is sent, convert to array
    interestedIn = [interestedInInput.trim()];
  }
  const message = messageInput?.trim() || "";

  // --- Backend Validation ---
  if (!name || !email || !phone) {
    return res
      .status(400)
      .json({ message: "Please fill in Name, Email, and Phone Number." });
  }

  try {
    // --- Check for existing user by email OR phone number ---
    const existingUser = await User.findOne({
      $or: [{ email: email }, { phone: phone }],
    }).lean();

    if (existingUser) {
      let conflictMessage =
        "This record cannot be added because of a duplicate entry.";
      if (existingUser.email === email) {
        conflictMessage =
          "This email address is already registered. Please use a different email.";
      } else if (existingUser.phone === phone) {
        conflictMessage =
          "This phone number is already registered. Please use a different number.";
      }
      return res.status(400).json({ message: conflictMessage });
    }

    const newUser = new User({
      name,
      email,
      phone,
      company,
      role,
      interestedIn,
      message,
    });

    const savedUser = await newUser.save();

    // --- Success Response to Frontend ---
    return res
      .status(201)
      .json({ message: "Registration successful! We will contact you soon." });
  } catch (dbError) {
    // Catch errors from findOne or save operations
    console.error(
      "!!! Error during database operation in /api/submit:",
      dbError
    );
    // If it's a validation error from Mongoose (e.g., required field missing despite frontend check failing)
    if (dbError.name === "ValidationError") {
      return res.status(400).json({ message: dbError.message });
    }
    // Otherwise, assume internal server error
    return res
      .status(500)
      .json({
        message: "An internal server error occurred. Please try again later.",
        error: dbError.message,
      });
  }
});

// === Fetch Leads Route ===
app.get("/api/leads", async (req, res) => {
  try {
    const users = await User.find().sort({ createdAt: -1 }).lean();
    res.status(200).json(users);
  } catch (error) {
    console.error("Error fetching leads:", error);
    res
      .status(500)
      .json({ message: "Failed to fetch leads.", error: error.message });
  }
});

// === Delete Lead Route ===
app.delete("/api/leads/:id", async (req, res) => {
  try {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ message: "Invalid lead ID format." });
    }
    const deletedUser = await User.findByIdAndDelete(id);
    if (!deletedUser) {
      return res.status(404).json({ message: "Lead not found." });
    }
    res.status(200).json({ message: "Lead deleted successfully." });
  } catch (error) {
    console.error(`Error deleting lead with ID (${req.params.id}):`, error);
    res
      .status(500)
      .json({
        message: "Internal Server Error occurred while deleting.",
        error: error.message,
      });
  }
});

// === Submissions Management Endpoints ===

// Get all form submissions
app.get("/api/submissions", async (req, res) => {
  try {
    // Fetch all submissions from the User collection (same as leads)
    const submissions = await User.find().sort({ createdAt: -1 }).lean();
    res.status(200).json({
      success: true,
      submissions,
    });
  } catch (error) {
    console.error("Error fetching submissions:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch submissions",
      error: error.message,
    });
  }
});

// Delete a single submission
app.delete("/api/submissions/:id", async (req, res) => {
  try {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid submission ID format",
      });
    }
    const deletedSubmission = await User.findByIdAndDelete(id);
    if (!deletedSubmission) {
      return res.status(404).json({
        success: false,
        message: "Submission not found",
      });
    }
    res.status(200).json({
      success: true,
      message: "Submission deleted successfully",
    });
  } catch (error) {
    console.error("Error deleting submission:", error);
    res.status(500).json({
      success: false,
      message: "Failed to delete submission",
      error: error.message,
    });
  }
});

// Bulk delete submissions
app.post("/api/submissions/bulk-delete", async (req, res) => {
  try {
    const { ids } = req.body;

    if (!ids || !Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({
        success: false,
        message: "Invalid request: ids array is required",
      });
    }

    // Validate all IDs
    const invalidIds = ids.filter((id) => !mongoose.Types.ObjectId.isValid(id));
    if (invalidIds.length > 0) {
      return res.status(400).json({
        success: false,
        message: `Invalid ObjectId(s): ${invalidIds.join(", ")}`,
      });
    }

    const result = await User.deleteMany({
      _id: { $in: ids },
    });

    res.status(200).json({
      success: true,
      message: `${result.deletedCount} submissions deleted successfully`,
      count: result.deletedCount,
    });
  } catch (error) {
    console.error("Error bulk deleting submissions:", error);
    res.status(500).json({
      success: false,
      message: "Failed to delete submissions",
      error: error.message,
    });
  }
});

// --- Basic Root Route ---
app.get("/", (req, res) => {
  res.status(200).send("Atorix Backend is running.");
});

// --- Global Error Handler ---
app.use((err, req, res, next) => {
  if (err.message === "Not allowed by CORS") {
    console.error(
      `CORS Error caught by global handler: ${err.message} from origin ${req.header("Origin")}`
    );
    return res.status(403).json({ message: "Access denied by CORS policy." });
  }
  console.error(
    "!!! Unhandled Error Caught by Global Handler:",
    err.stack || err
  );
  res
    .status(500)
    .json({ message: "An unexpected internal server error occurred." });
});

// --- Start Server ---
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

