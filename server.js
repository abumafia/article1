const express = require('express');
const mongoose = require('mongoose');
const cloudinary = require('cloudinary').v2;
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');
const sanitizeHtml = require('sanitize-html');
const { exec } = require('child_process');
const xml2js = require('xml2js');

dotenv.config();

// Initialize Express
const app = express();
const PORT = process.env.PORT || 3000;

// Eng oson yechim - CSP'ni vaqtincha o'chirish:
app.use(helmet({
    contentSecurityPolicy: false
}));

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Rate limiting
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100
});
app.use('/api/', apiLimiter);

// Database connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb+srv://abumafia0:abumafia0@abumafia.h1trttg.mongodb.net/article11?appName=abumafia');

// MongoDB Schemas & Models
// YANGI schema:
const articleSchema = new mongoose.Schema({
    title: { type: String, required: true, index: true },
    slug: { type: String, required: true, unique: true, index: true },
    author: { type: String, required: true, index: true },
    // YANGI: Kun/Oy/Yil uchun maydonlar
    publicationDate: { type: Date, required: true }, // <-- Yangi maydon
    abstract: { type: String, required: true },
    introduction: { type: String, required: true },
    body: [{ 
        heading: String,
        content: String 
    }],
    conclusion: { type: String, required: true },
    references: [String],
    coverImage: { type: String, required: true },
    pdfUrl: { type: String, required: true },
    views: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

const ratingSchema = new mongoose.Schema({
    articleId: { type: mongoose.Schema.Types.ObjectId, ref: 'Article', index: true },
    rating: { type: Number, min: 1, max: 5, required: true },
    userIp: { type: String, required: true },
    createdAt: { type: Date, default: Date.now, expires: '30d' } // Auto delete after 30 days
});

const commentSchema = new mongoose.Schema({
    articleId: { type: mongoose.Schema.Types.ObjectId, ref: 'Article', index: true },
    name: { type: String, default: 'Anonymous' },
    comment: { type: String, required: true },
    userIp: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});

const contactMessageSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true },
    subject: { type: String, required: true },
    message: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});

const Article = mongoose.model('Article', articleSchema);
const Rating = mongoose.model('Rating', ratingSchema);
const Comment = mongoose.model('Comment', commentSchema);
const ContactMessage = mongoose.model('ContactMessage', contactMessageSchema);

// Cloudinary configuration
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// File upload configuration
const storage = multer.memoryStorage();
const upload = multer({ 
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 } // 10MB limit
});

// Authentication middleware
const authenticateAdmin = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        if (decoded.username === process.env.ADMIN_USERNAME) {
            next();
        } else {
            res.status(403).json({ error: 'Invalid credentials' });
        }
    } catch (error) {
        res.status(401).json({ error: 'Invalid token' });
    }
};

// Email transporter
const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    secure: false,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Generate slug from title
function generateSlug(title) {
    return title
        .toLowerCase()
        .replace(/[^\w\s-]/g, '')
        .replace(/\s+/g, '-')
        .replace(/--+/g, '-')
        .trim();
}

// Generate sitemap
async function generateSitemap() {
    try {
        const articles = await Article.find({}, 'slug updatedAt').sort({ createdAt: -1 });
        
        const urlset = {
            $: {
                xmlns: 'http://www.sitemaps.org/schemas/sitemap/0.9'
            },
            url: [
                {
                    loc: `${process.env.BASE_URL || 'http://localhost:3000'}/`,
                    lastmod: new Date().toISOString().split('T')[0],
                    changefreq: 'daily',
                    priority: '1.0'
                },
                {
                    loc: `${process.env.BASE_URL || 'http://localhost:3000'}/articles.html`,
                    lastmod: new Date().toISOString().split('T')[0],
                    changefreq: 'daily',
                    priority: '0.8'
                },
                {
                    loc: `${process.env.BASE_URL || 'http://localhost:3000'}/about.html`,
                    changefreq: 'monthly',
                    priority: '0.5'
                },
                {
                    loc: `${process.env.BASE_URL || 'http://localhost:3000'}/contact.html`,
                    changefreq: 'monthly',
                    priority: '0.5'
                }
            ]
        };

        articles.forEach(article => {
            urlset.url.push({
                loc: `${process.env.BASE_URL || 'http://localhost:3000'}/article.html?slug=${article.slug}`,
                lastmod: article.updatedAt.toISOString().split('T')[0],
                changefreq: 'weekly',
                priority: '0.7'
            });
        });

        const builder = new xml2js.Builder();
        const xml = builder.buildObject({ urlset });
        
        fs.writeFileSync(path.join(__dirname, 'public', 'sitemap.xml'), xml);
        console.log('Sitemap generated successfully');
    } catch (error) {
        console.error('Error generating sitemap:', error);
    }
}

// Generate robots.txt
function generateRobotsTxt() {
    const baseUrl = process.env.BASE_URL || 'http://localhost:3000';
    const robotsTxt = `User-agent: *
Allow: /
Disallow: /admin.html
Disallow: /api/admin/

Sitemap: ${baseUrl}/sitemap.xml
`;
    fs.writeFileSync(path.join(__dirname, 'public', 'robots.txt'), robotsTxt);
}

// API Routes

// Admin login
app.post('/api/admin/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (username === process.env.ADMIN_USERNAME && 
            password === process.env.ADMIN_PASSWORD) {
            
            const token = jwt.sign(
                { username },
                process.env.JWT_SECRET,
                { expiresIn: '24h' }
            );
            
            res.json({ token });
        } else {
            res.status(401).json({ error: 'Invalid credentials' });
        }
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Upload article
app.post('/api/admin/articles', authenticateAdmin, upload.fields([
    { name: 'coverImage', maxCount: 1 },
    { name: 'pdfFile', maxCount: 1 }
]), async (req, res) => {
    try {
        const { title, author, publicationDate, abstract, introduction, body, conclusion, references } = req.body;
        
        // Upload cover image to Cloudinary
        const coverImageResult = await new Promise((resolve, reject) => {
            const stream = cloudinary.uploader.upload_stream(
                { folder: 'articles/covers', resource_type: 'image' },
                (error, result) => {
                    if (error) reject(error);
                    else resolve(result);
                }
            );
            stream.end(req.files['coverImage'][0].buffer);
        });

        // Upload PDF to Cloudinary
        const pdfResult = await new Promise((resolve, reject) => {
            const stream = cloudinary.uploader.upload_stream(
                { folder: 'articles/pdfs', resource_type: 'raw' },
                (error, result) => {
                    if (error) reject(error);
                    else resolve(result);
                }
            );
            stream.end(req.files['pdfFile'][0].buffer);
        });

        const slug = generateSlug(title);
        
        const article = new Article({
            title: sanitizeHtml(title),
            slug,
            author: sanitizeHtml(author),
            publicationDate: new Date(publicationDate), // <-- Yangi maydon
            abstract: sanitizeHtml(abstract),
            introduction: sanitizeHtml(introduction),
            body: JSON.parse(body).map(section => ({
                heading: sanitizeHtml(section.heading),
                content: sanitizeHtml(section.content)
            })),
            conclusion: sanitizeHtml(conclusion),
            references: JSON.parse(references || '[]').map(ref => sanitizeHtml(ref)),
            coverImage: coverImageResult.secure_url,
            pdfUrl: pdfResult.secure_url
        });

        await article.save();
        
        // Regenerate sitemap
        generateSitemap();
        
        res.json({ 
            success: true, 
            article: {
                id: article._id,
                slug: article.slug
            }
        });
    } catch (error) {
        console.error('Upload error:', error);
        res.status(500).json({ error: 'Upload failed' });
    }
});

// Get latest articles
app.get('/api/articles/latest', async (req, res) => {
    try {
        const articles = await Article.find()
            .sort({ createdAt: -1 })
            .limit(6)
            .select('title slug author publicationDate abstract coverImage createdAt');
        
        res.json(articles);
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Get article by slug
app.get('/api/articles/:slug', async (req, res) => {
    try {
        const article = await Article.findOne({ slug: req.params.slug });
        
        if (!article) {
            return res.status(404).json({ error: 'Article not found' });
        }
        
        // Increment views
        article.views += 1;
        await article.save();
        
        res.json(article);
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Search articles
app.get('/api/articles/search/:query', async (req, res) => {
    try {
        const query = req.params.query;
        
        const articles = await Article.find({
            $or: [
                { title: { $regex: query, $options: 'i' } },
                { author: { $regex: query, $options: 'i' } },
                { abstract: { $regex: query, $options: 'i' } }
            ]
        })
        .sort({ createdAt: -1 })
        .select('title slug author publicationDate abstract coverImage');
        
        res.json(articles);
    } catch (error) {
        res.status(500).json({ error: 'Search failed' });
    }
});

// Paginated articles
app.get('/api/articles/page/:page', async (req, res) => {
    try {
        const page = parseInt(req.params.page) || 1;
        const limit = 12;
        const skip = (page - 1) * limit;
        
        const [articles, total] = await Promise.all([
            Article.find()
                .sort({ createdAt: -1 })
                .skip(skip)
                .limit(limit)
                .select('title slug author publicationDate abstract coverImage'),
            Article.countDocuments()
        ]);
        
        res.json({
            articles,
            totalPages: Math.ceil(total / limit),
            currentPage: page,
            totalArticles: total
        });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Submit rating
app.post('/api/articles/:id/rate', async (req, res) => {
    try {
        const { rating } = req.body;
        const userIp = req.ip;
        
        // Check if user already rated
        const existingRating = await Rating.findOne({
            articleId: req.params.id,
            userIp
        });
        
        if (existingRating) {
            return res.status(400).json({ error: 'You have already rated this article' });
        }
        
        const newRating = new Rating({
            articleId: req.params.id,
            rating: Math.min(5, Math.max(1, parseInt(rating))),
            userIp
        });
        
        await newRating.save();
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Rating failed' });
    }
});

// Submit comment
app.post('/api/articles/:id/comment', async (req, res) => {
    try {
        const { name, comment } = req.body;
        const userIp = req.ip;
        
        // Rate limiting per IP
        const recentComments = await Comment.countDocuments({
            userIp,
            createdAt: { $gt: new Date(Date.now() - 5 * 60 * 1000) } // Last 5 minutes
        });
        
        if (recentComments >= 3) {
            return res.status(429).json({ error: 'Too many comments. Please wait 5 minutes.' });
        }
        
        const newComment = new Comment({
            articleId: req.params.id,
            name: sanitizeHtml(name || 'Anonymous'),
            comment: sanitizeHtml(comment),
            userIp
        });
        
        await newComment.save();
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Comment failed' });
    }
});

// Get comments
app.get('/api/articles/:id/comments', async (req, res) => {
    try {
        const comments = await Comment.find({ articleId: req.params.id })
            .sort({ createdAt: -1 })
            .limit(50);
        
        res.json(comments);
    } catch (error) {
        res.status(500).json({ error: 'Failed to load comments' });
    }
});

// Contact form
app.post('/api/contact', async (req, res) => {
    try {
        const { name, email, subject, message } = req.body;
        
        // Basic spam check
        if (message.includes('http://') || message.includes('https://') || 
            message.includes('.com') || message.includes('buy now')) {
            return res.status(400).json({ error: 'Message contains suspicious content' });
        }
        
        // Save to database
        const contactMessage = new ContactMessage({
            name: sanitizeHtml(name),
            email: sanitizeHtml(email),
            subject: sanitizeHtml(subject),
            message: sanitizeHtml(message)
        });
        
        await contactMessage.save();
        
        // Send email
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: process.env.SUPPORT_EMAIL,
            subject: `Contact Form: ${subject}`,
            html: `
                <h2>New Contact Message</h2>
                <p><strong>Name:</strong> ${name}</p>
                <p><strong>Email:</strong> ${email}</p>
                <p><strong>Subject:</strong> ${subject}</p>
                <p><strong>Message:</strong></p>
                <p>${message}</p>
                <hr>
                <p>Received at: ${new Date().toISOString()}</p>
            `
        };
        
        await transporter.sendMail(mailOptions);
        
        res.json({ success: true });
    } catch (error) {
        console.error('Contact error:', error);
        res.status(500).json({ error: 'Message sending failed' });
    }
});

// Get article statistics
app.get('/api/stats', async (req, res) => {
    try {
        const [totalArticles, totalViews, latestArticle] = await Promise.all([
            Article.countDocuments(),
            Article.aggregate([{ $group: { _id: null, total: { $sum: "$views" } } }]),
            Article.findOne().sort({ createdAt: -1 }).select('createdAt')
        ]);
        
        res.json({
            totalArticles,
            totalViews: totalViews[0]?.total || 0,
            platformSince: latestArticle?.createdAt || new Date()
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to get stats' });
    }
});

// Generate and serve sitemap
app.get('/sitemap.xml', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'sitemap.xml'));
});

// Generate and serve robots.txt
app.get('/robots.txt', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'robots.txt'));
});

// Initialize sitemap and robots.txt
generateSitemap();
generateRobotsTxt();

// Start server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Admin panel: http://localhost:${PORT}/admin.html`);
});
