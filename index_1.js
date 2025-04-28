// Required packages
const express = require('express');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();

// Middleware
app.use(express.json());
app.use(cookieParser());

// Secret keys (in production, store these in environment variables)
const ACCESS_TOKEN_SECRET = 'your-access-token-secret';
const REFRESH_TOKEN_SECRET = 'your-refresh-token-secret';

// Store refresh tokens (in production, use a database)
let refreshTokens = [];

// Middleware to verify access token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    console.log(authHeader);
    
    const token = authHeader && authHeader.split(' ')[1];
console.log(token);

    if (!token) {
        return res.sendStatus(401);
    }

    jwt.verify(token, ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) {
            return res.sendStatus(403);
        }
        req.user = user;
        next();
    });
};

// Login route
app.post('/login', (req, res) => {
    // Authenticate user (dummy authentication)
    const username = req.body.username;
    const user = { username: username };

    // Generate access token (short-lived, e.g., 15 minutes)
    const accessToken = jwt.sign(user, ACCESS_TOKEN_SECRET, { expiresIn: '1m' });
    
    // Generate refresh token (long-lived, e.g., 7 days)
    const refreshToken = jwt.sign(user, REFRESH_TOKEN_SECRET, { expiresIn: '7d' });
    
    // Store refresh token
    refreshTokens.push(refreshToken);

    // Set refresh token in HTTP-only cookie
    res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: false, // Use in production
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    res.json({ accessToken });
});

// Route to refresh access token
app.post('/refresh-token', (req, res) => {
    const refreshToken = req.cookies.refreshToken;
    console.log(refreshToken);
    
    if (!refreshToken) {
        return res.sendStatus(401);
    }

    if (!refreshTokens.includes(refreshToken)) {
        console.log("fiaed verf");
        
        return res.sendStatus(403);
    }

    jwt.verify(refreshToken, REFRESH_TOKEN_SECRET, (err, user) => {
        if (err) {
            console.log("failed verify");
            
            return res.sendStatus(403);
        }

        // Generate new access token
        const accessToken = jwt.sign(
            { username: user.username },
            ACCESS_TOKEN_SECRET,
            { expiresIn: '15m' }
        );

        res.json({ accessToken });
    });
});

// Logout route
app.post('/logout', (req, res) => {
    const refreshToken = req.cookies.refreshToken;
    
    // Remove refresh token from storage
    refreshTokens = refreshTokens.filter(token => token !== refreshToken);
    
    // Clear refresh token cookie
    res.clearCookie('refreshToken');
    
    res.sendStatus(204);
});

// Protected route example
app.get('/protected', authenticateToken, (req, res) => {
    res.json({ message: 'Protected data', user: req.user });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ message: 'Something went wrong!' });
});

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});