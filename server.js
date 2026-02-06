const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const fs = require('fs');
const path = require('path');
import { fileURLToPath } from "url";
const __dirname = path.dirname(__filename);
require('dotenv').config();

const app = express();
const __filename = fileURLToPath(import.meta.url);

// Middleware
app.use(cors({
  origin: "*"
}));
app.use(express.json());
app.use(express.static('public'));
app.use("/public", express.static(path.join(__dirname, "public")));

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI)
  .then(() => {
    console.log('MongoDB connected');
  })
  .catch(err => console.log(err));

// User Schema for Authentication
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true, trim: true },
  email: { type: String, unique: true, required: true, lowercase: true },
  password: { type: String, required: true },
  created_at: { type: Date, default: Date.now }
});

// Method to compare passwords
userSchema.methods.comparePassword = async function(password) {
  return await bcrypt.compare(password, this.password);
};

// Schemas
const profileSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  full_name: String,
  bio: String,
  website: String,
  avatar_url: String,
  projects_count: { type: Number, default: 0 },
  views_count: { type: Number, default: 0 },
  following_count: { type: Number, default: 0 },
  created_at: { type: Date, default: Date.now },
  updated_at: { type: Date, default: Date.now }
});

const skillSchema = new mongoose.Schema({
  name: { type: String, required: true },
  icon: String,
  order_index: { type: Number, default: 0 },
  created_at: { type: Date, default: Date.now }
});

const projectSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: String,
  image_urls: [{ type: String, required: true }],
  project_url: String,
  technologies: [String],
  likes: { type: Number, default: 0 },
  order_index: { type: Number, default: 0 },
  created_at: { type: Date, default: Date.now }
});

// Comment Schema
const commentSchema = new mongoose.Schema({
  projectId: { type: String, required: true },
  userId: { type: String, required: true },
  username: { type: String, required: true },
  text: { type: String, required: true },
  created_at: { type: Date, default: Date.now }
});

// Visitor Schema (for tracking followers via IP)
const visitorSchema = new mongoose.Schema({
  ip: { type: String, required: true, unique: true },
  visited_at: { type: Date, default: Date.now }
});

// Models
const User = mongoose.model('User', userSchema);
const Profile = mongoose.model('Profile', profileSchema);
const Skill = mongoose.model('Skill', skillSchema);
const Project = mongoose.model('Project', projectSchema);
const Comment = mongoose.model('Comment', commentSchema);
const Visitor = mongoose.model('Visitor', visitorSchema);

// Routes

// ========== AUTHENTICATION ROUTES ==========

// Sign Up Route
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    console.log('Signup attempt:', { username, email });

    // Validation
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(409).json({ error: 'Email or username already exists' });
    }

    // Hash password BEFORE saving
    const hashedPassword = await bcrypt.hash(password, 10);
    console.log('Password hashed');

    // Create new user with hashed password
    const user = new User({ username, email, password: hashedPassword });
    console.log('User created, saving...');
    await user.save();
    console.log('User saved successfully');

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id, username: user.username },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '7d' }
    );

    res.status(201).json({
      message: 'User created successfully',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email
      }
    });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Sign In Route
app.post('/api/auth/signin', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validation
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Compare passwords
    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id, username: user.username },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Signed in successfully',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Verify Token Route (Optional - for checking if token is valid)
app.post('/api/auth/verify', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }

    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET || 'your-secret-key'
    );

    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }

    res.json({
      valid: true,
      user: {
        id: user._id,
        username: user.username,
        email: user.email
      }
    });
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// ========== COMMENT ROUTES ==========

// Get comments for a project
app.get('/api/projects/:projectId/comments', async (req, res) => {
  try {
    const comments = await Comment.find({ projectId: req.params.projectId })
      .sort({ created_at: -1 });
    res.json(comments);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Add comment (only for logged in users)
app.post('/api/projects/:projectId/comments', async (req, res) => {
  try {
    const { text, userId, username } = req.body;

    // Validation
    if (!text || !userId || !username) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    if (text.trim().length < 1 || text.trim().length > 500) {
      return res.status(400).json({ error: 'Comment must be between 1 and 500 characters' });
    }

    // Create comment
    const comment = new Comment({
      projectId: req.params.projectId,
      userId,
      username,
      text: text.trim()
    });

    await comment.save();
    res.status(201).json(comment);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete comment (only by comment author)
app.delete('/api/comments/:commentId', async (req, res) => {
  try {
    const { userId } = req.body;
    const comment = await Comment.findById(req.params.commentId);

    if (!comment) {
      return res.status(404).json({ error: 'Comment not found' });
    }

    if (comment.userId !== userId) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    await Comment.findByIdAndDelete(req.params.commentId);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ========== CONTACT ROUTES ==========

// Configure nodemailer transporter
const transporter = nodemailer.createTransport({
  service: process.env.EMAIL_SERVICE || 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD,
  },
});

// Send contact email
app.post('/api/contact', async (req, res) => {
  try {
    const { name, email, subject, message } = req.body;

    // Validation
    if (!name || !email || !subject || !message) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    if (message.trim().length < 1) {
      return res.status(400).json({ error: 'Message cannot be empty' });
    }

    // Email to admin (portfolio owner)
    const adminMailOptions = {
      from: process.env.EMAIL_USER,
      to: process.env.CONTACT_EMAIL_RECIPIENT,
      subject: `New Contact Form Submission: ${subject}`,
      html: `
        <h2>New Contact Form Submission</h2>
        <p><strong>Name:</strong> ${name}</p>
        <p><strong>Email:</strong> ${email}</p>
        <p><strong>Subject:</strong> ${subject}</p>
        <p><strong>Message:</strong></p>
        <p>${message.replace(/\n/g, '<br>')}</p>
      `,
    };

    // Email to user (confirmation)
    const userMailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'We received your message',
      html: `
        <h2>Thank you for reaching out!</h2>
        <p>Hi ${name},</p>
        <p>We received your message and will get back to you as soon as possible.</p>
        <p><strong>Your message:</strong></p>
        <p>${message.replace(/\n/g, '<br>')}</p>
        <br>
        <p>Best regards,<br>The Portfolio Team</p>
      `,
    };

    // Send both emails
    await transporter.sendMail(adminMailOptions);
    await transporter.sendMail(userMailOptions);

    res.json({ 
      success: true, 
      message: 'Message sent successfully! Check your email for confirmation.' 
    });
  } catch (err) {
    console.error('Contact email error:', err);
    res.status(500).json({ error: 'Failed to send email. Please try again later.' });
  }
});

// Profile Routes
app.get('/api/profile', async (req, res) => {
  try {
    // Get client IP
    const clientIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.socket.remoteAddress;
    
    // Check if this IP has visited before
    let visitor = await Visitor.findOne({ ip: clientIp });

    if (!visitor) {
      // New visitor - create entry and increment views count
      visitor = new Visitor({ ip: clientIp });
      await visitor.save();

      // Increment views_count in profile
      let profile = await Profile.findOne();
      if (profile) {
        // Backfill from legacy followers_count if present
        if (typeof profile.views_count === 'undefined' && typeof profile.followers_count !== 'undefined') {
          profile.views_count = profile.followers_count || 0;
        }
        profile.views_count = (profile.views_count || 0) + 1;
        await profile.save();
      }
    }

    // Return profile with current views count (migrate legacy field if necessary)
    const profile = await Profile.findOne();
    if (profile && typeof profile.views_count === 'undefined' && typeof profile.followers_count !== 'undefined') {
      profile.views_count = profile.followers_count || 0;
      await profile.save();
    }
    res.json(profile || {});
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/profile', async (req, res) => {
  try {
    let profile = await Profile.findOne();
    if (!profile) {
      profile = new Profile(req.body);
    } else {
      Object.assign(profile, req.body);
    }
    await profile.save();
    res.json(profile);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/profile', async (req, res) => {
  try {
    const profile = await Profile.findOneAndUpdate({}, req.body, { new: true });
    res.json(profile);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Visitor tracking - get follower count
app.get('/api/followers', async (req, res) => {
  try {
    const profile = await Profile.findOne();
    // prefer views_count, fall back to legacy followers_count
    const count = profile?.views_count ?? profile?.followers_count ?? 0;
    res.json({ views_count: count });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get visitor stats (for debugging)
app.get('/api/visitors/stats', async (req, res) => {
  try {
    const visitorCount = await Visitor.countDocuments();
    res.json({ total_visitors: visitorCount });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Skills Routes
app.get('/api/skills', async (req, res) => {
  try {
    const skills = await Skill.find().sort({ order_index: 1 });
    res.json(skills);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/skills', async (req, res) => {
  try {
    const skill = new Skill(req.body);
    await skill.save();
    res.json(skill);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/skills/:id', async (req, res) => {
  try {
    const skill = await Skill.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json(skill);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/skills/:id', async (req, res) => {
  try {
    await Skill.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Projects Routes
app.get('/api/projects', async (req, res) => {
  try {
    const projects = await Project.find().sort({ order_index: 1 });
    res.json(projects);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/projects', async (req, res) => {
  try {
    const project = new Project(req.body);
    await project.save();
    res.json(project);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/projects/:id', async (req, res) => {
  try {
    const project = await Project.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json(project);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/projects/:id', async (req, res) => {
  try {
    await Project.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Like Project Route
app.patch('/api/projects/:id/like', async (req, res) => {
  try {
    const { action } = req.body; // 'like' or 'unlike'
    const projectId = req.params.id;
    const increment = action === 'like' ? 1 : -1;
    
    // Check if it's a MongoDB ObjectId
    if (mongoose.Types.ObjectId.isValid(projectId)) {
      const project = await Project.findByIdAndUpdate(
        projectId,
        { $inc: { likes: increment } },
        { new: true }
      );
      return res.json(project);
    }
    
    // Otherwise, try to find in data.json (for explore items)
    const dataPath = path.join(__dirname, 'data.json');
    const rawData = fs.readFileSync(dataPath, 'utf8');
    const data = JSON.parse(rawData);
    
    let found = false;
    const categories = ['projects', 'experiments', 'hackathons', 'side_ideas', 'iot_works'];
    
    for (const category of categories) {
      if (data[category]) {
        const project = data[category].find(p => p._id === projectId || p.id === projectId);
        if (project) {
          project.likes = (project.likes || 0) + increment;
          // Ensure likes doesn't go below 0
          if (project.likes < 0) project.likes = 0;
          
          // Write back to file
          fs.writeFileSync(dataPath, JSON.stringify(data, null, 2));
          found = true;
          return res.json(project);
        }
      }
    }
    
    if (!found) {
      return res.status(404).json({ error: 'Project not found' });
    }
  } catch (err) {
    console.error('Error updating like:', err);
    res.status(500).json({ error: err.message });
  }
});

// Explore Route - Load all categories data
app.get('/api/explore', (req, res) => {
  try {
    const dataPath = path.join(__dirname, 'data.json');
    const rawData = fs.readFileSync(dataPath, 'utf8');
    const data = JSON.parse(rawData);
    
    // Return all explore categories
    res.json({
      projects: data.projects || [],
      experiments: data.experiments || [],
      hackathons: data.hackathons || [],
      side_ideas: data.side_ideas || [],
      iot_works: data.iot_works || []
    });
  } catch (err) {
    console.error('Error fetching explore data:', err);
    res.status(500).json({ error: err.message });
  }
});

// Active Projects Route - Load ongoing/active projects
app.get('/api/active-projects', (req, res) => {
  try {
    const dataPath = path.join(__dirname, 'data.json');
    const rawData = fs.readFileSync(dataPath, 'utf8');
    const data = JSON.parse(rawData);
    
    // Return active projects sorted by order_index
    const activeProjects = (data.active_projects || []).sort((a, b) => a.order_index - b.order_index);
    res.json(activeProjects);
  } catch (err) {
    console.error('Error fetching active projects:', err);
    res.status(500).json({ error: err.message });
  }
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
