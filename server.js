import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import fs from "fs";
import path from "path";
import { Resend } from "resend";
import dotenv from "dotenv";
import { fileURLToPath } from "url";

dotenv.config();

const resend = new Resend(process.env.RESEND_API_KEY);

const app = express();

// ES module dirname fix
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Middleware
app.use(cors({ origin: "*" }));
app.use(express.json());

// Serve public folder
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

// Send contact email
app.post("/api/contact", async (req, res) => {
  try {
    const { name, email, subject, message } = req.body;

    if (!name || !email || !subject || !message) {
      return res.status(400).json({ error: "All fields are required" });
    }

    // Respond immediately
    res.json({
      success: true,
      message: "Message sent successfully",
    });

    // 1️⃣ Mail to YOU (admin)
    await resend.emails.send({
      from: "Portfolio Contact <onboarding@resend.dev>",
      to: process.env.CONTACT_EMAIL_RECIPIENT,
      replyTo: email,
      subject: subject,
      html: `
        <h2>New Contact Message</h2>
        <p><b>Name:</b> ${name}</p>
        <p><b>Email:</b> ${email}</p>
        <p><b>Subject:</b> ${subject}</p>
        <p><b>Message:</b></p>
        <p>${message.replace(/\n/g, "<br>")}</p>
      `,
    });

    // 2️⃣ Confirmation mail to USER
    await resend.emails.send({
      from: "Shivam | Portfolio <onboarding@resend.dev>",
      to: email,
      subject: "Thanks for contacting me!",
      html: `
        <p>Hi ${name},</p>
        <p>Thanks for reaching out 🙌</p>
        <p>I’ve received your message and will get back to you soon.</p>

        <hr />

        <p><b>Your message:</b></p>
        <p>${message.replace(/\n/g, "<br>")}</p>

        <br />
        <p>— Shivam</p>
      `,
    });

  } catch (error) {
    console.error("Resend error:", error);
  }
});

// Helper function to get normalized client IP
const getClientIp = (req) => {
  let ip = null;
  
  // Try multiple headers for IP detection
  // x-forwarded-for header (could be comma-separated list)
  const xForwardedFor = req.headers['x-forwarded-for'];
  if (xForwardedFor) {
    ip = xForwardedFor.split(',')[0].trim();
    if (ip && ip !== 'unknown') {
      console.log('Got IP from x-forwarded-for:', ip);
      return ip;
    }
  }
  
  // Try cf-connecting-ip (Cloudflare)
  if (req.headers['cf-connecting-ip']) {
    ip = req.headers['cf-connecting-ip'];
    console.log('Got IP from cf-connecting-ip:', ip);
    return ip;
  }
  
  // Try x-real-ip
  if (req.headers['x-real-ip']) {
    ip = req.headers['x-real-ip'];
    console.log('Got IP from x-real-ip:', ip);
    return ip;
  }
  
  // Fallback to direct socket connection
  let remoteAddress = req.socket?.remoteAddress || req.connection?.remoteAddress;
  
  // Normalize IPv6-mapped IPv4 addresses (e.g., ::ffff:127.0.0.1)
  if (remoteAddress && remoteAddress.startsWith('::ffff:')) {
    remoteAddress = remoteAddress.slice(7); // Remove ::ffff: prefix
  }
  
  if (remoteAddress && remoteAddress !== 'unknown' && remoteAddress !== '::1' && remoteAddress !== '127.0.0.1') {
    console.log('Got IP from socket:', remoteAddress);
    return remoteAddress;
  }
  
  // Fallback - use socket remoteAddress even if it's localhost (for testing)
  ip = remoteAddress || 'unknown';
  console.log('Fallback IP:', ip);
  return ip;
};

// Profile Routes
app.get('/api/profile', async (req, res) => {
  try {
    // Get client IP (normalized)
    const clientIp = getClientIp(req);
    console.log('===== Profile Access =====');
    console.log('Client IP:', clientIp);
    
    // Check if visitor exists before upsert
    const existingVisitor = await Visitor.findOne({ ip: clientIp });
    console.log('Existing visitor found:', !!existingVisitor);
    
    // Use updateOne with upsert to handle concurrent requests safely
    const result = await Visitor.updateOne(
      { ip: clientIp },
      { $set: { visited_at: new Date() } },
      { upsert: true }
    );
    
    // If upsertedId exists, this is a new visitor
    const isNewVisitor = !!result.upsertedId;
    console.log('UpdateOne result - Upserted:', !!result.upsertedId, 'Matched:', result.matchedCount, 'Modified:', result.modifiedCount);

    if (isNewVisitor) {
      console.log('NEW VISITOR - Incrementing view count');
      // Increment views_count in profile
      let profile = await Profile.findOne();
      if (profile) {
        // Backfill from legacy followers_count if present
        if (typeof profile.views_count === 'undefined' && typeof profile.followers_count !== 'undefined') {
          profile.views_count = profile.followers_count || 0;
        }
        profile.views_count = (profile.views_count || 0) + 1;
        console.log('New view count:', profile.views_count);
        await profile.save();
      }
    } else {
      console.log('RETURNING VISITOR - Not incrementing');
    }

    // Return profile with current views count
    const profile = await Profile.findOne();
    if (profile && typeof profile.views_count === 'undefined' && typeof profile.followers_count !== 'undefined') {
      profile.views_count = profile.followers_count || 0;
      await profile.save();
    }
    console.log('Returning profile with views_count:', profile?.views_count);
    console.log('==========================');
    res.json(profile || {});
  } catch (err) {
    console.error('Profile error:', err);
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
