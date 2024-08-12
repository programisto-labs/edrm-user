const express = require('express');
const User = require('../models/user.model');
const auth = require('endurance-core/lib/auth');

const router = express.Router();

const getUserByIdOrEmail = async (idOrEmail) => {
  if (typeof idOrEmail === 'object' && idOrEmail.email) {
    return await User.findOne({ email: idOrEmail.email });
  }
  return await User.findById(idOrEmail);
};

const validateUserPassword = async (user, password) => {
  return user.comparePassword(password);
};

const storeUserRefreshToken = async (userId, refreshToken) => {
  await User.updateOne({ _id: userId }, { refreshToken });
};

const getUserByRefreshToken = async (refreshToken) => {
  return await User.findOne({ refreshToken });
};

const deleteRefreshToken = async (refreshToken) => {
  await User.updateOne({ refreshToken }, { $unset: { refreshToken: 1 } });
};

auth.initializeAuth(
  getUserByIdOrEmail,         // Fonction pour obtenir l'utilisateur par ID ou email
  validateUserPassword,       // Fonction pour valider le mot de passe de l'utilisateur
  storeUserRefreshToken,      // Fonction pour stocker le refresh token
  getUserByRefreshToken,      // Fonction pour obtenir l'utilisateur par refresh token
  deleteRefreshToken          // Fonction pour supprimer le refresh token
);

// Route d'inscription utilisateur
router.post('/register', auth.asyncHandler(async (req, res) => {
  const user = new User(req.body);
  await user.save();
  res.status(201).json({ message: 'User registered successfully' });
}));

// Route de connexion utilisateur (génère un JWT et un refresh token)
router.post('/login', auth.authenticateAndGenerateTokens());

// Route protégée pour le profil utilisateur
router.get('/profile', auth.authenticateJWT(), (req, res) => {
  res.json(req.user);
});

module.exports = router;
