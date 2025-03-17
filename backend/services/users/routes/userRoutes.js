const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');
const auth = require('../middleware/auth');
const {body} = require('express-validator');

// Validation pour l'inscription
const registerValidation = [
    body('username')
    .trim()
    .isLength({min: 3})
    .withMessage('Le nom d\'utilisateur doit contenir au moins 3 caractères'),
    body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Email invalide'),
    body('password')
    .isLength({min: 6})
    .withMessage('Le mot de passe doit contenir au moins 6 caractères')
];

// Routes publiques
router.post('/register', userController.register);
router.post('/login', userController.login);

// Routes protégées
router.get('/', auth, userController.getAllUsers);
router.get('/:id', auth, userController.getUserById);
router.put('/:id', auth, userController.updateUser);
router.delete('/:id', auth, userController.deleteUser);

module.exports = router;