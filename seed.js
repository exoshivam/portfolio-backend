const mongoose = require('mongoose');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

// Load data from JSON file
const dataFilePath = path.join(__dirname, 'data.json');
const { profile: sampleProfile, skills: sampleSkills, projects: sampleProjects } = JSON.parse(
  fs.readFileSync(dataFilePath, 'utf8')
);

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.log('Connection error:', err));

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

// Models
const Profile = mongoose.model('Profile', profileSchema);
const Skill = mongoose.model('Skill', skillSchema);
const Project = mongoose.model('Project', projectSchema);

// Seeding Function
async function seed() {
  try {
    // Clear existing data
    await Profile.deleteMany({});
    await Skill.deleteMany({});
    await Project.deleteMany({});
    console.log('Cleared existing data');

    // Insert sample data
    const profile = await Profile.create(sampleProfile);
    console.log('✓ Profile created:', profile.username);

    const skills = await Skill.insertMany(sampleSkills);
    console.log(`✓ ${skills.length} skills created`);

    // Remove _id from projects to let MongoDB generate ObjectIds
    const projectsData = sampleProjects.map(({ _id, ...rest }) => rest);
    const projects = await Project.insertMany(projectsData);
    console.log(`✓ ${projects.length} projects created`);

    console.log('\n✅ Database seeded successfully!');
    console.log('\nYour portfolio now has:');
    console.log(`- Username: ${profile.username}`);
    console.log(`- ${skills.length} skills`);
    console.log(`- ${projects.length} projects`);

    process.exit(0);
  } catch (err) {
    console.error('❌ Error seeding database:', err);
    process.exit(1);
  }
}

// Run the seed function
seed();