const express = require('express');
const User = require('../models/user.model');
const Role = require('../models/role.model');
const auth = require('endurance-core/lib/auth');

const router = express.Router();

// Fonctions spécifiques au module user
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

// Surcharge des fonctions par défaut dans auth.js avec celles spécifiques au module user
auth.initializeAuth({
  getUserById: getUserByIdOrEmail,
  validatePassword: validateUserPassword,
  storeRefreshToken: storeUserRefreshToken,
  getStoredRefreshToken: getUserByRefreshToken,
  deleteStoredRefreshToken: deleteRefreshToken,
  checkUserPermissions,
  restrictToOwner,
});

// Routes spécifiques pour les utilisateurs

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
  const allowedUpdates = ['name', 'email', 'password']; // Champs que l'utilisateur peut mettre à jour
  const updates = Object.keys(req.body);

  // Filtre les champs interdits comme 'role' ou 'permissions'
  const isValidOperation = updates.every(update => allowedUpdates.includes(update));

  if (!isValidOperation) {
    return res.status(400).json({ message: 'Invalid updates!' });
  }

  // Appliquer les mises à jour autorisées
  updates.forEach(update => req.user[update] = req.body[update]);
  
  // Si l'utilisateur change son mot de passe, s'assurer que le hash est mis à jour
  if (req.body.password) {
    req.user.password = req.body.password;
  }

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

// Route pour rafraîchir le token JWT
router.post('/refresh-token', auth.refreshJWT());

// Route pour révoquer un refresh token (logout)
router.post('/revoke-token', auth.revokeRefreshToken());

module.exports = router;
