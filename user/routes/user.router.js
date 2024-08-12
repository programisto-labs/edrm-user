const express = require('express');
const User = require('../models/user.model');
const auth = require('endurance-core/lib/auth');

const router = express.Router();

// Fonction pour obtenir l'utilisateur par ID ou email
const getUserByIdOrEmail = async (idOrEmail) => {
  if (typeof idOrEmail === 'object' && idOrEmail.email) {
    return await User.findOne({ email: idOrEmail.email });
  }
  return await User.findById(idOrEmail);
};

// Fonction pour valider le mot de passe de l'utilisateur
const validateUserPassword = async (user, password) => {
  return user.comparePassword(password);
};

// Fonction pour stocker le refresh token
const storeUserRefreshToken = async (userId, refreshToken) => {
  await User.updateOne({ _id: userId }, { refreshToken });
};

// Fonction pour obtenir l'utilisateur par refresh token
const getUserByRefreshToken = async (refreshToken) => {
  return await User.findOne({ refreshToken });
};

// Fonction pour supprimer le refresh token
const deleteRefreshToken = async (refreshToken) => {
  await User.updateOne({ refreshToken }, { $unset: { refreshToken: 1 } });
};

// Initialiser l'authentification avec les fonctions spécifiques à l'utilisateur
auth.initializeAuth(
  getUserByIdOrEmail,         // Fonction pour obtenir l'utilisateur par ID ou email
  validateUserPassword,       // Fonction pour valider le mot de passe de l'utilisateur
  storeUserRefreshToken,      // Fonction pour stocker le refresh token
  getUserByRefreshToken,      // Fonction pour obtenir l'utilisateur par refresh token
  deleteRefreshToken          // Fonction pour supprimer le refresh token
);

// Middleware combiné pour vérifier JWT et ensuite restreindre l'accès aux propriétaires de la ressource
const restrictToOwner = (getResourceOwnerIdFn) => {
  return [
    auth.authenticateJWT(), // Vérifie d'abord que l'utilisateur est authentifié
    async (req, res, next) => {
      try {
        const resourceOwnerId = await getResourceOwnerIdFn(req);

        if (req.user.id !== resourceOwnerId.toString()) {
          return res.status(403).json({ message: 'Access denied: You do not own this resource' });
        }

        next();
      } catch (err) {
        res.status(500).json({ message: 'Error checking resource ownership', error: err.message });
      }
    },
  ];
};

// Middleware combiné pour vérifier JWT et les permissions
const checkUserPermissions = (requiredPermissions, bypassForSuperadmin = false) => {
    return [
      auth.authenticateJWT(), // Vérifie d'abord que l'utilisateur est authentifié
      async (req, res, next) => {
        if (bypassForSuperadmin && req.user.role.name === 'superadmin') {
          return next(); // Bypass pour le superadmin
        }
  
        const role = await req.user.populate('role').execPopulate();
        const userPermissions = role.permissions.map((perm) => perm.name);
        
        const hasPermission = requiredPermissions.every((perm) => userPermissions.includes(perm));
        if (!hasPermission) {
          return res.status(403).json({ message: 'Access denied: Insufficient permissions' });
        }
  
        next();
      },
    ];
  };
  

// Route d'inscription utilisateur
router.post('/register', auth.asyncHandler(async (req, res) => {
  const user = new User(req.body);
  await user.save();
  res.status(201).json({ message: 'User registered successfully' });
}));

// Route de connexion utilisateur (génère un JWT et un refresh token)
router.post('/login', auth.authenticateAndGenerateTokens());

// Route protégée pour le profil utilisateur (JWT et accès à son propre profil)
router.get('/profile', restrictToOwner((req) => req.user.id), (req, res) => {
  res.json(req.user);
});

// Route protégée pour mettre à jour le profil utilisateur (JWT et accès à son propre profil)
router.patch('/profile', restrictToOwner((req) => req.user.id), auth.asyncHandler(async (req, res) => {
  Object.assign(req.user, req.body);
  await req.user.save();
  res.json(req.user);
}));

// Route protégée pour supprimer un utilisateur (JWT et vérification des permissions)
router.delete('/profile', checkUserPermissions(['canDeleteUser']), auth.asyncHandler(async (req, res) => {
  await req.user.remove();
  res.json({ message: 'User deleted successfully' });
}));

// Route pour assigner un rôle à un utilisateur
router.post('/assign-role', 
    auth.authenticateJWT(), 
    checkUserPermissions(['canAssignRoles'], true),  // Superadmin bypass
    auth.asyncHandler(async (req, res) => {
      const { userId, roleId } = req.body;
  
      if (!userId || !roleId) {
        return res.status(400).json({ message: 'User ID and Role ID are required' });
      }
  
      const user = await User.findById(userId);
      const role = await Role.findById(roleId);
  
      if (!user || !role) {
        return res.status(404).json({ message: 'User or Role not found' });
      }
  
      user.role = roleId;
      await user.save();
  
      res.json({ message: 'Role assigned successfully', user });
  }));

module.exports = router;
