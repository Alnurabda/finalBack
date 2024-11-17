
router.post('/register', async (req, res) => {
    const { username, password, firstName, lastName, age, gender } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const twoFASecret = speakeasy.generateSecret().base32;

    const newUser  = new User({ username, password: hashedPassword, firstName, lastName, age, gender, twoFASecret });
    await newUser .save();

    // Send welcome email
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL,
            pass: process.env.EMAIL_PASSWORD,
        },
    });

    const mailOptions = {
        from: process.env.EMAIL,
        to: req.body.username,
        subject: 'Welcome to Our Platform',
        text: 'Thank you for registering!',
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.log(error);
        } else {
            console.log('Email sent: ' + info.response);
        }
    });

    res.redirect('/auth/login');
});

// Login
router.get('/login', (req, res) => {
    res.render('login');
});

router.post('/login', async (req, res) => {
    const { username, password, twoFACode } = req.body;
    const user = await User.findOne({ username });

    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).send('Invalid credentials');
    }

    if (user.twoFAEnabled) {
        const verified = speakeasy.totp.verify({
            secret: user.twoFASecret,
            encoding: 'base32',
            token: twoFACode,
        });

        if (!verified) {
            return res.status(401).send('Invalid 2FA code');
        }
    }

    req.session.userId = user._id;
    req.session.role = user.role;
    res.redirect('/');
});

// Logout
router.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

module.exports = router;
