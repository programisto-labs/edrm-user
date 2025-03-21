import User from '../models/user.model.js';
import jwt from 'jsonwebtoken';
import passport from 'passport';
import crypto from 'crypto';
import { EnduranceAuthMiddleware, EnduranceAccessControl, EnduranceAuth } from 'endurance-core';
import { Request, Response, NextFunction } from 'express';

const secret = process.env.JWT_SECRET || 'default_secret';
//const refreshSecret = process.env.JWT_REFRESH_SECRET || 'default_refresh_secret';

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
        await user.populate('role').execPopulate();
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
      const user = await User.findOne({ email });
      if (!user) {
        throw new Error('User not found');
      }
      user.refreshToken = refreshToken;
      await user.save();
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

  public authenticateLocalAndGenerateTokens = (req: Request, res: Response, next: NextFunction): Promise<void> => {
    return new Promise((resolve) => {
      passport.authenticate('local', { session: false }, async (err: any, user: typeof User, info: any) => {
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

          await this.storeRefreshToken(user.email, refreshToken);
          res.json({ token, refreshToken });
          resolve();
        });
      })(req, res, next);
    });
  };

  public authenticateAzureAndGenerateTokens = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    return new Promise((resolve) => {
      passport.authenticate('azure_ad_oauth2', { session: false }, async (err: any, user: typeof User, info: any) => {
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

          await this.storeRefreshToken(user.email, refreshToken);
          (req as any).tokens = { token, refreshToken };
          next();
          resolve();
        });
      })(req, res, next);
    });
  };

  public generateAzureTokens = (req: Request, res: Response, next: NextFunction): Promise<void> => {
    return new Promise((resolve) => {
      passport.authenticate('azure_ad_oauth2', { session: false }, async (err: any, user: typeof User, info: any) => {
        if (err || !user) {
          res.status(400).json({
            message: 'Authentication failed',
            error: err,
          });
          return resolve();
        }

        req.login(user, { session: false }, async (loginErr: any) => {
          if (loginErr) {
            res.status(500).json({ message: 'Login failed', error: loginErr });
            return resolve();
          }

          try {
            const token = this.generateToken(user);
            const refreshToken = this.generateRefreshToken();

            await this.storeRefreshToken(user.email, refreshToken);

            res.json({
              accessToken: token,
              refreshToken: refreshToken,
            });
            resolve();
          } catch (err) {
            res.status(500).json({ message: 'Token generation failed', error: err });
            resolve();
          }
        });
      })(req, res, next);
    });
  };

  public refreshJwt = (req: Request, res: Response, next: NextFunction): Promise<void> => {
    return new Promise((resolve) => {
      const { refreshToken } = req.body;

      if (!refreshToken) {
        res.status(400).json({ message: 'Refresh token is required' });
        return resolve();
      }

      this.getStoredRefreshToken(refreshToken)
        .then(storedRefreshToken => {
          if (!storedRefreshToken) {
            res.status(401).json({ message: 'Invalid refresh token' });
            return resolve();
          }

          return this.getUserById(storedRefreshToken.userId);
        })
        .then(user => {
          if (!user) {
            res.status(401).json({ message: 'Invalid refresh token' });
            return resolve();
          }

          const newToken = this.generateToken(user);
          res.json({ token: newToken });
          resolve();
        })
        .catch(err => {
          const message = err instanceof Error ? err.message : 'Unknown error';
          res.status(500).json({ message: 'Error refreshing token', error: message });
          resolve();
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

  public isAuthenticated = (): any => {
    return passport.authenticate(['jwt', 'azure_jwt'], { session: false });
  };

  public handleAuthError = (err: any, req: Request, res: Response, next: NextFunction): void => {
    if (err.name === 'UnauthorizedError') {
      res.status(401).json({ message: 'Invalid or expired token' });
    } else {
      next(err);
    }
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
