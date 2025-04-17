import User from '../models/user.model.js';
import Role from '../models/role.model.js';
import jwt from 'jsonwebtoken';
import passport from 'passport';
import crypto from 'crypto';
import { EnduranceAuthMiddleware, EnduranceAccessControl, EnduranceAuth } from 'endurance-core';
import { Request, Response, NextFunction } from 'express';
import { EnduranceDocumentType } from 'endurance-core';
import { Strategy as AzureAdOAuth2Strategy } from 'passport-azure-ad-oauth2';
import { Strategy as JwtStrategy, ExtractJwt } from 'passport-jwt';
import { Strategy as LocalStrategy } from 'passport-local';

const secret = process.env.JWT_SECRET || 'default_secret';
const refreshSecret = process.env.JWT_REFRESH_SECRET || 'default_refresh_secret';

type UserDocument = EnduranceDocumentType<typeof User> & {
  email: string;
  _id: string;
};

interface RequestWithUser extends Request {
  user?: UserDocument;
  tokens?: { token: string; refreshToken: string };
}

passport.serializeUser(function (user: any, done) {
  done(null, user);
});

passport.deserializeUser(function (user: any, done) {
  done(null, user);
});

class CustomAccessControl extends EnduranceAccessControl {
  public checkUserPermissions = async (
    permissions: string[],
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const user = req.user as any;
      if (!user) {
        res.status(401).json({ message: 'User not authenticated' });
        return;
      }

      if (user.role?.name === 'superadmin') {
        return next();
      }

      if (!user.role) {
        await user.populate({
          path: 'role',
          model: Role,
          options: { strictPopulate: false }
        }).execPopulate();
      }

      const userPermissions = user.role?.permissions?.map((perm: any) => perm.name) || [];
      const hasPermission = permissions.every((perm) => userPermissions.includes(perm));

      if (!hasPermission) {
        res.status(403).json({ message: 'Access denied: Insufficient permissions' });
        return;
      }

      next();
    } catch (error) {
      next(error);
    }
  };

  public restrictToOwner = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const resourceOwnerId = await this.getResourceOwnerId(req);
      const user = req.user as any;

      if (!user) {
        res.status(401).json({ message: 'User not authenticated' });
        return;
      }

      if (user.id !== resourceOwnerId.toString()) {
        res.status(403).json({ message: 'Access denied: You do not own this resource' });
        return;
      }

      next();
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      res.status(500).json({ message: 'Error checking resource ownership', error: message });
    }
  };

  private getResourceOwnerId = async (req: Request): Promise<string> => {
    const user = req.user as any;
    if (!user?.id) {
      throw new Error('User ID not found');
    }
    return user.id;
  };
}

class CustomAuth extends EnduranceAuth {
  constructor() {
    super();
    this.configureAzureStrategy();
    this.configureJwtStrategy();
    this.configureLocalStrategy();
    this.configureAzureJwtStrategy();
  }

  private configureAzureStrategy(): void {
    if (process.env.LOGIN_AZURE_ACTIVATED === 'true') {
      const requiredEnvVars = [
        'AZURE_CLIENT_ID',
        'AZURE_CLIENT_SECRET',
        'AZURE_RESOURCE',
        'AZURE_TENANT',
        'AZURE_CALLBACK_URL'
      ];

      const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);
      if (missingVars.length > 0) {
        console.error('Azure AD OAuth2 configuration is incomplete. Missing variables:', missingVars);
        return;
      }

      const clientId = process.env.AZURE_CLIENT_ID;
      const clientSecret = process.env.AZURE_CLIENT_SECRET;
      const callbackURL = process.env.AZURE_CALLBACK_URL;
      const resource = process.env.AZURE_RESOURCE;
      const tenant = process.env.AZURE_TENANT;

      if (!clientId || !clientSecret || !callbackURL || !resource || !tenant) {
        console.error('Azure AD OAuth2 configuration is incomplete');
        return;
      }

      passport.use('azure_ad_oauth2', new AzureAdOAuth2Strategy({
        clientID: clientId,
        clientSecret: clientSecret,
        callbackURL: callbackURL,
        resource: resource,
        tenant: tenant,
        allowHttpForRedirectUrl: process.env.NODE_ENV === 'development'
      },
        async function (accessToken: string, refresh_token: string, params: any, profile: any, done: any) {
          try {
            const waadProfile = jwt.decode(params.id_token) as { upn: string; email?: string };
            if (!waadProfile || (!waadProfile.upn && !waadProfile.email)) {
              return done(new Error('Invalid Azure profile: missing email or upn'), null);
            }

            const email = waadProfile.email || waadProfile.upn;
            console.log('Looking for user with email:', email);
            const user = await User.findOne({ email }).select('+password');
            if (!user) {
              console.error('User not found in database:', email);
              return done(new Error('User not found. Please register first.'), null);
            }
            console.log('Found user in Azure strategy:', user);
            done(null, user);
          } catch (err) {
            console.error('Azure authentication error:', err);
            return done(err, null);
          }
        }));
    }
  }

  private configureJwtStrategy(): void {
    passport.use(
      new JwtStrategy(
        {
          jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
          secretOrKey: secret,
        },
        async (jwtPayload: any, done: any) => {
          try {
            const email = jwtPayload.email;
            const user = await this.getUserById({ email });
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
  }

  private configureLocalStrategy(): void {
    passport.use(
      new LocalStrategy(
        {
          usernameField: 'email',
          passwordField: 'password',
        },
        async (email: string, password: string, done: any) => {
          try {
            const user = await this.getUserById({ email });
            if (!user || !(await this.validatePassword(user, password))) {
              return done(null, false, { message: 'Incorrect email or password.' });
            }
            return done(null, user);
          } catch (err) {
            return done(err);
          }
        }
      )
    );
  }

  private configureAzureJwtStrategy(): void {
    passport.use(
      'azure_jwt',
      new JwtStrategy(
        {
          jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
          secretOrKey: secret,
          issuer: `https://sts.windows.net/${process.env.AZURE_TENANT}/`,
          audience: process.env.AZURE_CLIENT_ID,
        },
        async (jwtPayload: any, done: any) => {
          try {
            if (!jwtPayload.upn && !jwtPayload.email) {
              return done(new Error('Invalid token: missing email or upn'), false);
            }

            const email = jwtPayload.email || jwtPayload.upn;
            const user = await User.findOne({ email });

            if (!user) {
              return done(new Error('User not found'), false);
            }

            return done(null, user);
          } catch (err) {
            console.error('Azure JWT validation error:', err);
            return done(err, false);
          }
        }
      )
    );
  }

  public getUserById = async (idOrEmail: string | { email: string }): Promise<any> => {
    if (typeof idOrEmail === 'object' && idOrEmail.email) {
      return await User.findOne({ email: idOrEmail.email }).select('+password');
    }
    return await User.findById(idOrEmail).select('+password');
  };

  public validatePassword = async (user: any, password: string): Promise<boolean> => {
    return user.comparePassword(password);
  };

  public storeRefreshToken = async (email: string, refreshToken: string): Promise<void> => {
    try {
      const result = await User.updateOne(
        { email },
        { $set: { refreshToken } }
      );

      if (result.matchedCount === 0) {
        throw new Error('User not found');
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      throw new Error(`Error storing refresh token: ${message}`);
    }
  };

  public getStoredRefreshToken = async (refreshToken: string): Promise<any> => {
    return await User.findOne({ refreshToken });
  };

  public deleteStoredRefreshToken = async (refreshToken: string): Promise<void> => {
    await User.updateOne({ refreshToken }, { $unset: { refreshToken: 1 } });
  };

  public authenticateLocalAndGenerateTokens = (req: RequestWithUser, res: Response, next: NextFunction): Promise<void> => {
    return new Promise((resolve) => {
      passport.authenticate('local', { session: false }, async (err: any, user: UserDocument, info: any) => {
        if (err || !user) {
          res.status(400).json({
            message: 'Something is not right',
            user: user,
            err: err
          });
          return resolve();
        }

        req.login(user, { session: false }, async (err: any) => {
          if (err) {
            res.send(err);
            return resolve();
          }

          const token = this.generateToken(user);
          const refreshToken = this.generateRefreshToken();

          await this.storeRefreshToken((user as any).email, refreshToken);
          res.json({ token, refreshToken });
          resolve();
        });
      })(req, res, next);
    });
  };

  public authenticateAzureAndGenerateTokens = async (req: RequestWithUser, res: Response, next: NextFunction): Promise<void> => {
    return new Promise((resolve) => {
      passport.authenticate('azure_ad_oauth2', { session: false }, async (err: any, user: UserDocument, info: any) => {
        if (err || !user) {
          res.status(400).json({
            message: 'Something is not right',
            user: user,
            err: err
          });
          return resolve();
        }

        req.login(user, { session: false }, async (err: any) => {
          if (err) {
            res.send(err);
            return resolve();
          }

          const token = this.generateToken(user);
          const refreshToken = this.generateRefreshToken();

          await this.storeRefreshToken((user as any).email, refreshToken);
          (req as any).tokens = { token, refreshToken };
          next();
          resolve();
        });
      })(req, res, next);
    });
  };

  public generateAzureTokens = (req: RequestWithUser, res: Response, next: NextFunction): Promise<void> => {
    return new Promise((resolve) => {
      console.log('Starting Azure authentication...');
      passport.authenticate('azure_ad_oauth2', { session: false }, async (err: any, user: UserDocument, info: any) => {
        if (err) {
          console.error('Azure authentication error:', err);
          if (!res.headersSent) {
            res.status(400).json({
              message: 'Authentication failed',
              error: err.message
            });
          }
          return resolve();
        }

        if (!user) {
          console.error('No user found after Azure authentication');
          if (!res.headersSent) {
            res.status(401).json({
              message: 'User not found or not authorized'
            });
          }
          return resolve();
        }

        console.log('User found:', user.email);
        req.login(user, { session: false }, async (loginErr: any) => {
          if (loginErr) {
            console.error('Login error:', loginErr);
            if (!res.headersSent) {
              res.status(500).json({ message: 'Login failed', error: loginErr.message });
            }
            return resolve();
          }

          try {
            const token = this.generateToken(user);
            const refreshToken = this.generateRefreshToken();

            await this.storeRefreshToken(user.email, refreshToken);
            console.log('Tokens generated successfully');
            console.log('Generated token:', token);

            req.user = user;

            if (!res.headersSent) {
              res.json({
                accessToken: token,
                refreshToken: refreshToken,
                user: {
                  email: user.email,
                  id: user._id
                }
              });
            }
            next();
            resolve();
          } catch (err) {
            console.error('Token generation error:', err);
            if (!res.headersSent) {
              res.status(500).json({ message: 'Token generation failed', error: err instanceof Error ? err.message : 'Unknown error' });
            }
            resolve();
          }
        });
      })(req, res, next);
    });
  };

  public refreshJwt = async (req: Request, res: Response, next: NextFunction): Promise<{ accessToken: string }> => {
    return new Promise((resolve) => {
      const { refreshToken } = req.body;

      if (!refreshToken) {
        res.status(400).json({ message: 'Refresh token is required' });
        return resolve({ accessToken: '' });
      }

      this.getStoredRefreshToken(refreshToken)
        .then(storedRefreshToken => {
          if (!storedRefreshToken) {
            res.status(401).json({ message: 'Invalid refresh token' });
            return resolve({ accessToken: '' });
          }

          return this.getUserById(storedRefreshToken.userId);
        })
        .then(user => {
          if (!user) {
            res.status(401).json({ message: 'Invalid refresh token' });
            return resolve({ accessToken: '' });
          }

          const newToken = this.generateToken(user);
          res.json({ accessToken: newToken });
          resolve({ accessToken: newToken });
        })
        .catch(err => {
          const message = err instanceof Error ? err.message : 'Unknown error';
          res.status(500).json({ message: 'Error refreshing token', error: message });
          resolve({ accessToken: '' });
        });
    });
  };

  public revokeRefreshToken = (req: Request, res: Response, next: NextFunction): Promise<void> => {
    return new Promise((resolve) => {
      const { refreshToken } = req.body;

      if (!refreshToken) {
        res.status(400).json({ message: 'Refresh token is required' });
        return resolve();
      }

      this.deleteStoredRefreshToken(refreshToken)
        .then(() => {
          res.status(200).json({ message: 'Refresh token revoked' });
          resolve();
        })
        .catch(err => {
          const message = err instanceof Error ? err.message : 'Unknown error';
          res.status(500).json({ message: 'Error revoking refresh token', error: message });
          resolve();
        });
    });
  };

  public generateToken = (user: any): string => {
    if (!user || !user.email) {
      throw new Error('generateToken requires a user object with email');
    }
    return jwt.sign({ email: user.email }, secret, { expiresIn: '15m' });
  };

  public generateRefreshToken = (): string => {
    return crypto.randomBytes(40).toString('hex');
  };

  public isAuthenticated = (): ((req: Request, res: Response, next: NextFunction) => void) => {
    return (req: Request, res: Response, next: NextFunction): void => {
      passport.authenticate(['jwt', 'azure_jwt'], { session: false }, (err: any, user: any, info: any) => {
        if (err) {
          return next(err);
        }
        if (!user) {
          return res.status(401).json({ message: 'Unauthorized' });
        }
        req.user = user;
        next();
      })(req, res, next);
    };
  };

  public handleAuthError = (err: any, req: Request, res: Response, next: NextFunction): void => {
    if (err.name === 'UnauthorizedError') {
      res.status(401).json({ message: 'Invalid or expired token' });
    } else {
      next(err);
    }
  };

  public createNewUser = async (userData: any): Promise<any> => {
    const existingUser = await User.findOne({ email: userData.email });
    if (existingUser) {
      return existingUser;
    }

    const newUser = new User(userData);
    await newUser.save();
    return newUser;
  };

  public authorize = (checkPermissionsFn: (user: any, req: Request) => Promise<boolean>) => {
    return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        const hasPermission = await checkPermissionsFn(req.user, req);

        if (!hasPermission) {
          res.status(403).json({ message: 'Access denied: Insufficient permissions' });
          return;
        }

        next();
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Unknown error';
        res.status(500).json({ message: 'Authorization error', error: message });
      }
    };
  };
}

class CustomAuthMiddleware extends EnduranceAuthMiddleware {
  constructor() {
    const accessControl = new CustomAccessControl();
    const auth = new CustomAuth();
    super(accessControl, auth);
  }
}

const authMiddleware = new CustomAuthMiddleware();
EnduranceAuthMiddleware.setInstance(authMiddleware);

export default authMiddleware;
