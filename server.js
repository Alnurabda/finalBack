const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const dotenv = require('dotenv');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bodyParser = require('body-parser');
const multer = require('multer');
const { generateSecret, verifyToken } = require('./utils/2fa'); // Custom module for 2FA
const path = require('path');

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.log(err));

// Middleware
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
    secret: 'your_secret_key',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: process.env.MONGODB_URI })
}));

//

// Passport configuration
passport.use(new LocalStrategy(async (username, password, done) => {
    try {
        const user = await User.findOne({ username });
        if (!user) return done(null, false, { message: 'User not found' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return done(null, false, { message: 'Incorrect password' });

        return done(null, user);
    } catch (err) {
        return done(err);
    }
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (err) {
        done(err);
    }
});

app.use(passport.initialize());
app.use(passport.session());

// Nodemailer setup
const transporter = nodemailer.createTransport({
    service: 'Gmail',
    auth: {
        user: process.env.EMAIL,
        pass: process.env.EMAIL_PASSWORD
    }
});
// Middleware для проверки роли администратора
function ensureAdmin(req, res, next) {
    if (req.isAuthenticated() && req.user.role === 'admin') {
        return next();
    }
    res.status(403).send('Доступ запрещен.');
}

// Middleware для проверки роли редактора
function ensureEditor(req, res, next) {
    if (req.isAuthenticated() && (req.user.role === 'admin' || req.user.role === 'editor')) {
        return next();
    }
    res.status(403).send('Доступ запрещен.');
}

module.exports = { ensureAdmin, ensureEditor };


// Multer setup for image uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/'),
    filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});

const upload = multer({ storage });

// Routes

// Root Route
app.get('/', (req, res) => {
    if (req.isAuthenticated()) {
        return res.redirect('/main');
    }
    res.redirect('/login');
});

// Register Route
app.get('/register', (req, res) => {
    res.render('register');
});

app.post('/register', async (req, res) => {
    const { username, password, firstName, lastName, age, gender, email } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = new User({
            username,
            password: hashedPassword,
            firstName,
            lastName,
            age,
            gender,
            email
        });

        await newUser.save();

        // Send welcome email
        const mailOptions = {
            from: process.env.EMAIL,
            to: email,
            subject: 'Welcome to the Platform!',
            text: `Hello ${firstName},\n\nWelcome to our platform. We're glad to have you on board!`
        };
        await transporter.sendMail(mailOptions);

        res.redirect('/login');
    } catch (err) {
        console.error(err);
        res.redirect('/register');
    }


app.post('/login', async (req, res, next) => {
  passport.authenticate('local', async (err, user, info) => {
    if (err) {
      return next(err);
    }
    if (!user) {
      req.flash('error', 'Invalid username or password');
      return res.redirect('/login');
   }}) })
 
// In the app.js or an initial script
const isAdmin = process.env.CREATE_ADMIN === 'true';  // Check if admin creation is enabled

if (isAdmin) {
  const adminUser = new User({
    username: 'Alnura',
    password: bcrypt.hashSync('12345', 10),
    firstName: 'Alnura',
    lastName: 'Maxyutova',
    age: 19,
    gender: 'W',
    email: 'maxyutovaalnura131@gmail.com',
    role: 'admin', 
  });

  adminUser.save().then(() => console.log('Admin user created'));
}

app.get('/main', (req, res) => {
    if (!req.isAuthenticated()) {
        return res.redirect('/login');
    }
    res.render('main', { user: req.user });
});

// Admin and Editor Access
app.get('/admin', (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).send('Access Denied');
    }
    res.render('admin');
});

app.get('/editor', (req, res) => {
    if (req.user.role !== 'editor') {
        return res.status(403).send('Access Denied');
    }
    res.render('editor');
});

app.get('/login', (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect('/login');
  }

  if (req.user.role === 'admin') {
    return res.redirect('/admin'); // Redirect admins to the admin page
  } else if (req.user.role === 'editor') {
    return res.redirect('/editor'); // Redirect editors to the editor page
  }
  res.send('Unknown role, please contact admin.');
});

app.get('/admin', async (req, res) => {
  if (req.isAuthenticated() && req.user.role === 'admin') {
    try {
      // Fetch all blog posts from the database
      const blogPosts = await BlogPost.find().sort({ createdAt: -1 });

      // Render the admin.ejs file and pass the blog posts
      res.render('admin', { blogPosts });
    } catch (error) {
      console.error('Error fetching blog posts:', error);
      res.status(500).send('Error loading admin panel');
    }
  } else {
    res.status(403).send('Unauthorized');
  }
});


app.get('/admin/create', (req, res) => {
  if (req.isAuthenticated() && req.user.role === 'admin') {
    // Render the adminCreate.ejs file
    res.render('adminCreate');
  } else {
    res.status(403).send('Unauthorized');
  }
});


app.post('/admin/create', upload.single('image'), async (req, res) => {
  if (req.isAuthenticated() && req.user.role === 'admin') {
    const newBlogPost = new BlogPost({
      title: req.body.title,
      content: req.body.content,
      imageUrl: req.file.filename,
      author: req.user._id,  
    });

    await newBlogPost.save();

    res.redirect('/admin'); 
    res.send('Unauthorized');
  }
});

app.get('/admin/edit/:id', async (req, res) => {
  if (req.isAuthenticated() && req.user.role === 'admin') {
    try {
      const blogPost = await BlogPost.findById(req.params.id);
      if (!blogPost) {
        return res.status(404).send('Blog post not found');
      }

      // Render the adminEdit.ejs file and pass the blogPost data
      res.render('adminEdit', { blogPost });
    } catch (error) {
      console.error('Error fetching blog post:', error);
      res.status(500).send('Internal Server Error');
    }
  } else {
    res.status(403).send('Unauthorized');
  }
});


app.post('/admin/edit/:id', upload.single('image'), async (req, res) => {
  if (req.isAuthenticated() && req.user.role === 'admin') {
    const blogPost = await BlogPost.findById(req.params.id);
    if (!blogPost) {
      return res.send('Blog post not found');
    }

    // Update the blog post fields
    blogPost.title = req.body.title;
    blogPost.content = req.body.content;
    if (req.file) { // If a new image is uploaded, update it
      blogPost.imageUrl = req.file.filename;
    }

    await blogPost.save();
    res.redirect('/admin'); // Redirect back to the admin page after editing
  } else {
    res.send('Unauthorized');
  }
});


app.get('/admin/delete/:id', async (req, res) => {
  if (req.isAuthenticated() && req.user.role === 'admin') {
    const blogPost = await BlogPost.findById(req.params.id);
    if (!blogPost) {
      return res.send('Blog post not found');
    }

    const imagePath = path.join(__dirname, 'uploads', blogPost.imageUrl);
    fs.unlink(imagePath, (err) => {
      if (err) {
        console.error('Failed to delete image:', err);
      } else {
        console.log('Image deleted successfully');
      }
    });

    // Delete the blog post from the database
    await BlogPost.findByIdAndDelete(req.params.id);
    res.redirect('/admin'); // Redirect to admin page after deleting
  } else {
    res.send('Unauthorized');
  }
});


app.get('/editor', async (req, res) => {
  if (req.isAuthenticated() && req.user.role === 'editor') {
    try {
      // Fetch all blog posts from the database
      const blogPosts = await BlogPost.find().sort({ createdAt: -1 });

      // Render the editor.ejs file and pass the blogPosts data
      res.render('editor', { blogPosts });
    } catch (error) {
      console.error('Error fetching blog posts:', error);
      res.status(500).send('Internal Server Error');
    }
  } else {
    res.status(403).send('Unauthorized');
  }
});


// Route for handling image and text uploads for editors
app.post('/editor/upload', upload.single('image'), async (req, res) => {
  // Save the new blog post with the uploaded image
  const newBlogPost = new BlogPost({
    title: req.body.title,
    content: req.body.content,
    imageUrl: req.file.filename,  // Store the filename of the uploaded image
    author: req.user._id, // Reference to the user who created the post
  });

  await newBlogPost.save();

// Listen on Port
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
