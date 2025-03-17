const express = require('express');
const proxy = require('express-http-proxy');
const helmet = require('helmet');
const cors = require('cors');
const dotenv = require('dotenv');
dotenv.config();

const app = express();
const PORT = process.env.PORT_GATEWAY || 3000;

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());

// Proxy configuration
app.use('/api/users', proxy(process.env.PROXY_USERS, {timeout: 10000}));
app.use('/api/socialauth', proxy(process.env.PROXY_SOCIALAUTH, {timeout: 10000}));

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({status: 'OK'});
});

// Démarrer le serveur HTTPS
app.listen(PORT);
