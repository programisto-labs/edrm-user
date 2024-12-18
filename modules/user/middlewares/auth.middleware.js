import User from '../models/user.model.js';
import { auth, accessControl } from 'endurance-core/lib/auth.js';
import jwt from 'jsonwebtoken';
import passport from 'passport';
import { Strategy as JwtStrategy, ExtractJwt } from 'passport-jwt';
import { Strategy as LocalStrategy } from 'passport-local';
import { Strategy as AzureAdOAuth2Strategy } from 'passport-azure-ad-oauth2';

import crypto from 'crypto';

const secret = process.env.JWT_SECRET || 'default_secret';
const refreshSecret = process.env.JWT_REFRESH_SECRET || 'default_refresh_secret';

passport.serializeUser(function (user, done) {
  done(null, user);
});

passport.deserializeUser(function (user, done) {
  done(null, user);
});

const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

const getUserByIdOrEmail = async (idOrEmail) => {
  if (typeof idOrEmail === 'object' && idOrEmail.email) {
    return await User.findOne({ email: idOrEmail.email });
  }
  return await User.findById(idOrEmail);
};

const createNewUser = async (userData) => {
  const existingUser = await User.findOne({ email: userData.email });
  if (existingUser) {
    return existingUser;
  }

  const newUser = new User(userData);
  await newUser.save();
  return newUser;
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
    accessControl.isAuthenticated(),
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
    accessControl.isAuthenticated(),
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

const storeRefreshToken = async (email, refreshToken) => {
  try {
    const user = await User.findOne({ email });
    if (!user) {
      throw new Error('User not found');
    }
    user.refreshToken = refreshToken;
    await user.save();
  } catch (err) {
    throw new Error(`Error storing refresh token: ${err.message}`);
  }
};

const authenticateLocalAndGenerateTokens = () => {
  return asyncHandler((req, res, next) => {
    passport.authenticate('local', { session: false }, async (err, user, info) => {
      if (err || !user) {
        return res.status(400).json({
          message: 'Something is not right',
          user: user,
          err: err
        });
      }
      req.login(user, { session: false }, async (err) => {
        if (err) {
          res.send(err);
        }
        const token = generateToken(user);
        const refreshToken = generateRefreshToken();

        await storeRefreshToken(user.email, refreshToken);

        return res.json({ token, refreshToken });
      });
    })(req, res, next);
  });
};

const authenticateAzureAndGenerateTokens = () => {
  return asyncHandler((req, res, next) => {
    passport.authenticate('azure_ad_oauth2', { session: false }, async (err, user, info) => {
      if (err || !user) {
        console.error(err);
        return res.status(400).json({
          message: 'Something is not right',
          user: user,
          err: err
        });
      }
      req.login(user, { session: false }, async (err) => {
        if (err) {
          return res.send(err);
        }
        const token = generateToken(user);
        const refreshToken = generateRefreshToken();

        await storeRefreshToken(user.email, refreshToken);

        // Instead of returning a response, call next() to allow the next middleware to run
        req.tokens = { token, refreshToken };
        next();
      });
    })(req, res, next);
  });
};

const generateAzureTokens = (req, res) => {
  return asyncHandler((req, res, next) => {
    passport.authenticate('azure_ad_oauth2', { session: false }, async (err, user, info) => {
      if (err || !user) {
        console.error('Authentication error:', err);
        return res.status(400).json({
          message: 'Authentication failed',
          error: err,
        });
      }

      req.login(user, { session: false }, async (loginErr) => {
        if (loginErr) {
          console.error('Login error:', loginErr);
          return res.status(500).json({ message: 'Login failed', error: loginErr });
        }

        try {
          const token = generateToken(user);
          const refreshToken = generateRefreshToken();

          await storeRefreshToken(user.email, refreshToken);

          res.json({
            accessToken: token,
            refreshToken: refreshToken,
          });
        } catch (err) {
          console.error('Error generating tokens:', err);
          res.status(500).json({ message: 'Token generation failed', error: err });
        }
      });
    })(req, res, next);
  });
};

const configureJwtStrategy = () => {
  passport.use(
    new JwtStrategy(
      {
        jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
        secretOrKey: secret,
      },
      async (jwtPayload, done) => {
        try {
          console.log(jwtPayload);
          const email = jwtPayload.email;
          const user = await getUserByIdOrEmail({ email });
          if (user) {
            return done(null, user);
          } else {
            return done(null, false);
          }
        } catch (err) {
          return done(err, false);
        }
      }
    )
  );
};

const configureLocalStrategy = () => {
  passport.use(
    new LocalStrategy(
      {
        usernameField: 'email',
        passwordField: 'password',
      },
      async (email, password, done) => {
        try {
          const user = await getUserByIdOrEmail({ email });
          if (!user || !(await validateUserPassword(user, password))) {
            return done(null, false, { message: 'Incorrect email or password.' });
          }
          return done(null, user);
        } catch (err) {
          return done(err);
        }
      }
    )
  );
};

const configureAzureStrategy = () => {
  passport.use(new AzureAdOAuth2Strategy({
    clientID: process.env.AZURE_CLIENT_ID,
    clientSecret: process.env.AZURE_CLIENT_SECRET,
    callbackURL: process.env.AZURE_CALLBACK_URL || 'https://www.example.net/auth/azureadoauth2/callback',
    resource: process.env.AZURE_RESOURCE || '00000002-0000-0000-c000-000000000000',
    tenant: process.env.AZURE_TENANT || 'contoso.onmicrosoft.com',
    allowHttpForRedirectUrl: true
  },
    async function (accessToken, refresh_token, params, profile, done) {
      var waadProfile = jwt.decode(params.id_token);

      try {
        const user = await User.findOne({ email: waadProfile.upn });
        if (!user) {
          return done(new Error('user not created'), null);
        }
        done(null, user);
      } catch (err) {
        return done(err, null);
      }
    }));
};

const refreshJwt = () => {
  return asyncHandler(async (req, res) => {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({ message: 'Refresh token is required' });
    }

    try {
      const storedRefreshToken = await getUserByRefreshToken(refreshToken);
      if (!storedRefreshToken) {
        return res.status(401).json({ message: 'Invalid refresh token' });
      }

      const user = await getUserByIdOrEmail(storedRefreshToken.userId);
      if (!user) {
        return res.status(401).json({ message: 'Invalid refresh token' });
      }

      const newToken = generateToken(user);

      return res.json({ token: newToken });
    } catch (err) {
      return res.status(500).json({ message: 'Error refreshing token', error: err.message });
    }
  });
};

const revokeRefreshToken = () => {
  return asyncHandler(async (req, res) => {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({ message: 'Refresh token is required' });
    }

    try {
      await deleteRefreshToken(refreshToken);
      return res.status(200).json({ message: 'Refresh token revoked' });
    } catch (err) {
      return res.status(500).json({ message: 'Error revoking refresh token', error: err.message });
    }
  });
};

const isAuthenticated = () => {
  return passport.authenticate('jwt', { failureMessage: true });
};

const authorize = (checkPermissionsFn) => {
  return async (req, res, next) => {
    try {
      const hasPermission = await checkPermissionsFn(req.user, req);

      if (!hasPermission) {
        return res.status(403).json({ message: 'Access denied: Insufficient permissions' });
      }

      next();
    } catch (err) {
      res.status(500).json({ message: 'Authorization error', error: err.message });
    }
  };
};

const generateRefreshToken = () => {
  return crypto.randomBytes(40).toString('hex');
};

const generateToken = (user) => {
  if (!user || !user.email) {
    throw new Error('generateToken requires a user object with id and email');
  }
  return jwt.sign({ email: user.email }, secret, { expiresIn: '15m' });
};

const handleAuthError = (err, req, res, next) => {
  if (err.name === 'UnauthorizedError') {
    res.status(401).json({ message: 'Invalid or expired token' });
  } else {
    next(err);
  }
};

auth.initializeAuth({
  getUserFn: getUserByIdOrEmail,
  checkUserPermissionsFn: checkUserPermissions,
  restrictToOwnerFn: restrictToOwner,
  validatePasswordFn: validateUserPassword,
  storeRefreshTokenFn: storeUserRefreshToken,
  getStoredRefreshTokenFn: getUserByRefreshToken,
  deleteStoredRefreshTokenFn: deleteRefreshToken,
  createNewUserFn: createNewUser,
  authenticateLocalAndGenerateTokensFn: authenticateLocalAndGenerateTokens,
  authenticateAzureAndGenerateTokensFn: authenticateAzureAndGenerateTokens,
  generateAzureTokensFn: generateAzureTokens,
  configureJwtStrategyFn: configureJwtStrategy,
  configureLocalStrategyFn: configureLocalStrategy,
  configureAzureStrategyFn: configureAzureStrategy,
  refreshJwtFn: refreshJwt,
  revokeRefreshTokenFn: revokeRefreshToken,
  authenticateJwtFn: isAuthenticated,
  authorizeFn: authorize,
  generateRefreshTokenFn: generateRefreshToken,
  generateTokenFn: generateToken,
  handleAuthErrorFn: handleAuthError
});

export {
  getUserByIdOrEmail as getUserFn,
  validateUserPassword as validatePasswordFn,
  storeUserRefreshToken as storeRefreshTokenFn,
  getUserByRefreshToken as getStoredRefreshTokenFn,
  deleteRefreshToken as deleteStoredRefreshTokenFn,
  checkUserPermissions,
  authenticateLocalAndGenerateTokens,
  restrictToOwner,
  createNewUser as createNewUserFn,
};
