import User from '../models/user.model.js';
import auth from 'endurance-core/lib/auth.js';

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
    auth.authenticateJWT(), 
    async (req, res, next) => {
      if (bypassForSuperadmin && req.user.role.name === 'superadmin') {
        return next(); 
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
    auth.authenticateJWT(), 
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

auth.initializeAuth({
  getUserById: getUserByIdOrEmail,
  validatePassword: validateUserPassword,
  storeRefreshToken: storeUserRefreshToken,
  getStoredRefreshToken: getUserByRefreshToken,
  deleteStoredRefreshToken: deleteRefreshToken,
  checkUserPermissions,
  restrictToOwner,
});

export {
  checkUserPermissions,
  restrictToOwner,
};
