import { EnduranceRouter, EnduranceRequest, Response, NextFunction, type SecurityOptions, enduranceEmitter as emitter, enduranceEventTypes as eventTypes, EnduranceAuthMiddleware, EnduranceDocumentType } from 'endurance-core';
import User from '../models/user.model.js';
import Role from '../models/role.model.js';
import crypto from 'crypto';

class UserRouter extends EnduranceRouter {
  constructor() {
    super(EnduranceAuthMiddleware.getInstance());
  }

  setupRoutes(): void {
    const publicRoutes: SecurityOptions = {
      requireAuth: false
    };

    const authenticatedRoutes: SecurityOptions = {
      requireAuth: true
    };

    this.get('/test', publicRoutes, async (req: EnduranceRequest, res: Response, next: NextFunction) => {
      try {
        await this.checkAuth(req, res);
      } catch (error) {
        next(error);
      }
    });

    // Routes publiques
    this.get('/auth-methods', publicRoutes, async (req: EnduranceRequest, res: Response, next: NextFunction) => {
      await this.getAuthMethods(req, res, next);
    });

    this.get('/find', publicRoutes, async (req: EnduranceRequest, res: Response) => {
      await this.findUser(req, res);
    });

    this.post('/register', publicRoutes, async (req: EnduranceRequest, res: Response) => {
      await this.registerUser(req, res);
    });

    // Routes authentifiées
    this.get('/check-auth', authenticatedRoutes, async (req: EnduranceRequest, res: Response, next: NextFunction) => {
      try {
        await this.checkAuth(req, res);
      } catch (error) {
        next(error);
      }
    });

    if (process.env.LOGIN_LOCAL_ACTIVATED) {
      this.post('/login/local', publicRoutes, async (req: EnduranceRequest, res: Response, next: NextFunction) => {
        try {
          await this.localLogin(req, res);
        } catch (error) {
          next(error);
        }
      });

      this.post('/request-password-reset', publicRoutes, async (req: EnduranceRequest, res: Response, next: NextFunction) => {
        try {
          await this.requestPasswordReset(req, res);
        } catch (error) {
          next(error);
        }
      });

      this.post('/reset-password', publicRoutes, async (req: EnduranceRequest, res: Response, next: NextFunction) => {
        try {
          await this.resetPassword(req, res);
        } catch (error) {
          next(error);
        }
      });
    }

    if (process.env.LOGIN_AZURE_ACTIVATED === 'true') {
      this.setupAzureRoutes();
    }

    // Routes protégées avec permissions
    const profileRoutes: SecurityOptions = {
      requireAuth: true,
      permissions: ['manageProfile']
    };

    const adminRoutes: SecurityOptions = {
      requireAuth: true,
      permissions: ['manageUsers']
    };

    this.get('/profile', profileRoutes, async (req: EnduranceRequest, res: Response) => {
      await this.getProfile(req, res);
    });

    this.patch('/profile', profileRoutes, async (req: EnduranceRequest, res: Response) => {
      await this.updateProfile(req, res);
    });

    this.delete('/profile', adminRoutes, async (req: EnduranceRequest, res: Response, next: NextFunction) => {
      try {
        await this.deleteProfile(req, res);
      } catch (error) {
        next(error);
      }
    });

    this.post('/assign-role', adminRoutes, async (req: EnduranceRequest, res: Response, next: NextFunction) => {
      try {
        await this.assignRole(req, res);
      } catch (error) {
        next(error);
      }
    });

    this.post('/refresh-token', authenticatedRoutes, async (req: EnduranceRequest, res: Response, next: NextFunction) => {
      try {
        await this.refreshToken(req, res);
      } catch (error) {
        next(error);
      }
    });

    this.post('/revoke-token', authenticatedRoutes, async (req: EnduranceRequest, res: Response, next: NextFunction) => {
      try {
        await this.revokeToken(req, res);
      } catch (error) {
        next(error);
      }
    });
  }

  private getAuthMethods = async (req: EnduranceRequest, res: Response, next: NextFunction): Promise<void> => {
    try {
      const authMethods = {
        local: process.env.LOGIN_LOCAL_ACTIVATED === 'true',
        azure: process.env.LOGIN_AZURE_ACTIVATED === 'true'
      };
      res.json({ authMethods });
    } catch (error) {
      next(error);
    }
  };

  private checkAuth = async (req: EnduranceRequest, res: Response): Promise<void> => {
    res.json({ result: 'ok' });
  };

  private findUser = async (req: EnduranceRequest, res: Response): Promise<void> => {
    const { email } = req.query;
    const user = await User.findOne({ email });
    res.json(user);
  };

  private registerUser = async (req: EnduranceRequest, res: Response): Promise<void> => {
    const user = new User(req.body);
    await user.save();
    emitter.emit(eventTypes.userRegistered, user);
    res.status(201).json({ message: 'User registered successfully' });
  };

  private localLogin = async (req: EnduranceRequest, res: Response): Promise<void> => {
    emitter.emit(eventTypes.userLoggedIn, req.user);
    res.json({ message: 'User logged in successfully' });
  };

  private requestPasswordReset = async (req: EnduranceRequest, res: Response): Promise<void> => {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      res.status(404).json({ message: 'User not found' });
      return;
    }

    const resetToken = crypto.randomBytes(40).toString('hex');
    user.resetToken = resetToken;
    user.resetTokenExpiration = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes from now
    await user.save();

    emitter.emit('passwordResetRequested', { user, resetToken });

    res.json({ message: 'Password reset token generated' });
  };

  private resetPassword = async (req: EnduranceRequest, res: Response): Promise<void> => {
    const { resetToken, newPassword } = req.body;
    const user = await User.findOne({ resetToken, resetTokenExpiration: { $gt: Date.now() } });

    if (!user) {
      res.status(400).json({ message: 'Invalid or expired reset token' });
      return;
    }

    user.password = newPassword;
    user.resetToken = undefined;
    user.resetTokenExpiration = undefined;
    await user.save();

    emitter.emit('passwordReset', user);

    res.json({ message: 'Password has been reset successfully' });
  };

  private setupAzureRoutes(): void {
    if (!process.env.AZURE_CLIENT_ID ||
      !process.env.AZURE_CLIENT_SECRET ||
      !process.env.AZURE_RESOURCE ||
      !process.env.AZURE_TENANT ||
      !process.env.AZURE_CALLBACK_URL) {
      console.error('Error: Azure environment variables are not set. Azure login routes will not be loaded.');
    } else {
      const publicRoutes: SecurityOptions = {
        requireAuth: false
      };

      this.get('/login/azure', publicRoutes, async (req: EnduranceRequest, res: Response, next: NextFunction) => {
        try {
          await this.azureLogin(req, res);
        } catch (error) {
          next(error);
        }
      });
      this.post('/login/azure/exchange', publicRoutes, async (req: EnduranceRequest, res: Response, next: NextFunction) => {
        try {
          await this.azureExchange(req, res);
        } catch (error) {
          next(error);
        }
      });
    }
  }

  private azureLogin = async (req: EnduranceRequest, res: Response): Promise<void> => {
    emitter.emit(eventTypes.userLoggedIn, req.user);
    const loginCallbackUrl = process.env.AZURE_CALLBACK_URL;
    if (loginCallbackUrl) {
      return res.redirect(loginCallbackUrl);
    }
    res.json({ message: 'User logged in successfully' });
  };

  private azureExchange = async (req: EnduranceRequest, res: Response) => {
    emitter.emit(eventTypes.userLoggedIn, req.user);
    res.json({ message: 'User logged in successfully' });
  };

  private getProfile = async (req: EnduranceRequest, res: Response): Promise<void> => {
    res.json(req.user);
  };

  private updateProfile = async (req: EnduranceRequest, res: Response): Promise<void> => {
    if (!req.user) {
      res.status(401).json({ message: 'User not authenticated' });
      return;
    }

    const allowedUpdates = ['name', 'email', 'password'];
    const updates = Object.keys(req.body);

    const isValidOperation = updates.every(update => allowedUpdates.includes(update));

    if (!isValidOperation) {
      res.status(400).json({ message: 'Invalid updates!' });
      return;
    }

    updates.forEach(update => req.user[update] = req.body[update]);

    if (req.body.password) {
      req.user.password = req.body.password;
    }

    await req.user.save();
    emitter.emit(eventTypes.userProfileUpdated, req.user);
    res.json(req.user);
  };

  private deleteProfile = async (req: EnduranceRequest, res: Response): Promise<void> => {
    await req.user.remove();
    emitter.emit('userDeleted', req.user);
    res.json({ message: 'User deleted successfully' });
  };

  private assignRole = async (req: EnduranceRequest, res: Response): Promise<void> => {
    const { userId, roleId } = req.body;

    if (!userId || !roleId) {
      res.status(400).json({ message: 'User ID and Role ID are required' });
      return;
    }

    const user = await User.findById(userId);
    const role = await Role.findById(roleId);

    if (!user || !role) {
      res.status(404).json({ message: 'User or Role not found' });
      return;
    }

    user.role = roleId;
    await user.save();
    emitter.emit(eventTypes.roleAssigned, { user, role });
    res.json({ message: 'Role assigned successfully', user });
  };

  private refreshToken = async (req: EnduranceRequest, res: Response) => {
    res.json({ message: 'Token refreshed successfully' });
  };

  private revokeToken = async (req: EnduranceRequest, res: Response): Promise<void> => {
    res.json({ message: 'Token revoked successfully' });
  };
}

const userRouter = new UserRouter();
export default userRouter;
