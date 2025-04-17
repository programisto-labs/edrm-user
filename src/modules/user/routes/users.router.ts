import { EnduranceRouter, EnduranceRequest, Response, NextFunction, type SecurityOptions, enduranceEmitter as emitter, enduranceEventTypes as eventTypes, EnduranceAuthMiddleware, EnduranceDocumentType } from 'endurance-core';
import User from '../models/user.model.js';
import Role from '../models/role.model.js';
import crypto from 'crypto';

interface UserDocument extends EnduranceDocumentType<typeof User> {
  email: string;
  firstname: string;
  lastname: string;
  name: string;
  role: any;
  xpHistory: any[];
  completedQuests: any[];
  badges: any[];
  getLevel: () => number;
  getXPforNextLevel: () => number;
  createdAt: Date;
  updatedAt: Date;
}

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

    // Middleware de debug pour tracer les requêtes
    this.router.use((req: EnduranceRequest, res: Response, next: NextFunction) => {
      console.log('Request path:', req.path);
      console.log('Request headers:', req.headers);
      next();
    });

    // Routes publiques
    this.get('/auth-methods', publicRoutes, async (req: EnduranceRequest, res: Response) => {
      const authMethods = {
        local: process.env.LOGIN_LOCAL_ACTIVATED === 'true',
        azure: process.env.LOGIN_AZURE_ACTIVATED === 'true'
      };
      res.json({ authMethods });
    });

    this.get('/find', publicRoutes, async (req: EnduranceRequest, res: Response) => {
      const { email } = req.query;
      const user = await User.findOne({ email });
      res.json(user);
    });

    this.post('/register', publicRoutes, async (req: EnduranceRequest, res: Response) => {
      const user = new User(req.body);
      await user.save();
      emitter.emit(eventTypes.userRegistered, user);
      res.status(201).json({ message: 'User registered successfully' });
    });

    // Routes authentifiées
    this.get('/check-auth', authenticatedRoutes, async (req: EnduranceRequest, res: Response) => {
      res.json({ result: 'ok' });
    });

    if (process.env.LOGIN_LOCAL_ACTIVATED === 'true') {
      this.post('/login/local', publicRoutes, async (req: EnduranceRequest, res: Response, next: NextFunction) => {
        try {
          if (!this.authMiddleware?.auth) {
            throw new Error('Auth middleware not initialized');
          }
          await this.authMiddleware.auth.authenticateLocalAndGenerateTokens(req, res, next);
          emitter.emit(eventTypes.userLoggedIn, req.user);
          res.json({ message: 'User logged in successfully' });
        } catch (error) {
          next(error);
        }
      });

      this.post('/request-password-reset', publicRoutes, async (req: EnduranceRequest, res: Response) => {
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

        res.json({ message: 'Password reset token generated', resetToken });
      });

      this.post('/reset-password', publicRoutes, async (req: EnduranceRequest, res: Response) => {
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
      });
    }

    if (process.env.LOGIN_AZURE_ACTIVATED === 'true') {
      this.setupAzureRoutes();
    }

    // Routes protégées avec permissions
    const adminRoutes: SecurityOptions = {
      requireAuth: true,
      permissions: ['manageUsers']
    };

    this.get('/profile', authenticatedRoutes, async (req: EnduranceRequest, res: Response) => {

      if (!req.user) {
        res.status(401).json({ message: 'User not authenticated' });
        return;
      }

      try {
        const user = await User.findById(req.user._id)
          .select('-password -refreshToken')
          .populate({
            path: 'role',
            model: Role,
            options: { strictPopulate: false }
          })
          .exec() as unknown as UserDocument;

        if (!user) {
          res.status(404).json({ message: 'User not found' });
          return;
        }

        res.json({
          id: user._id,
          email: user.email,
          firstname: user.firstname,
          lastname: user.lastname,
          name: user.name,
          role: user.role,
          createdAt: user.createdAt,
          updatedAt: user.updatedAt
        });
      } catch (error) {
        console.error('Error fetching user profile:', error);
        res.status(500).json({ message: 'Error fetching user profile' });
      }
    });

    this.patch('/profile', authenticatedRoutes, async (req: EnduranceRequest, res: Response) => {
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
    });

    this.delete('/profile', adminRoutes, async (req: EnduranceRequest, res: Response) => {
      if (!req.user) {
        res.status(401).json({ message: 'User not authenticated' });
        return;
      }
      await req.user.remove();
      emitter.emit('userDeleted', req.user);
      res.json({ message: 'User deleted successfully' });
    });

    this.post('/assign-role', adminRoutes, async (req: EnduranceRequest, res: Response) => {
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
    });

    this.post('/refresh-token', authenticatedRoutes, async (req: EnduranceRequest, res: Response, next: NextFunction) => {
      try {
        if (!this.authMiddleware?.auth) {
          throw new Error('Auth middleware not initialized');
        }
        await this.authMiddleware.auth.refreshJwt(req, res, next);
      } catch (error) {
        next(error);
      }
    });

    this.post('/revoke-token', authenticatedRoutes, async (req: EnduranceRequest, res: Response, next: NextFunction) => {
      try {
        if (!this.authMiddleware?.auth) {
          throw new Error('Auth middleware not initialized');
        }
        await this.authMiddleware.auth.revokeRefreshToken(req, res, next);
      } catch (error) {
        next(error);
      }
    });
  }

  private setupAzureRoutes(): void {
    if (!process.env.AZURE_CLIENT_ID ||
      !process.env.AZURE_CLIENT_SECRET ||
      !process.env.AZURE_RESOURCE ||
      !process.env.AZURE_TENANT ||
      !process.env.AZURE_CALLBACK_URL) {
      console.error('Error: Azure environment variables are not set. Azure login routes will not be loaded.');
      return;
    }

    const publicRoutes: SecurityOptions = {
      requireAuth: false
    };

    this.get('/login/azure', publicRoutes, async (req: EnduranceRequest, res: Response, next: NextFunction) => {
      try {
        if (!this.authMiddleware?.auth) {
          throw new Error('Auth middleware not initialized');
        }
        await this.authMiddleware.auth.authenticateAzureAndGenerateTokens(req, res, next);
        emitter.emit(eventTypes.userLoggedIn, req.user);
        const loginCallbackUrl = process.env.AZURE_CALLBACK_URL;
        if (loginCallbackUrl) {
          return res.redirect(loginCallbackUrl);
        }
        res.json({ message: 'User logged in successfully' });
      } catch (error) {
        next(error);
      }
    });

    this.post('/login/azure/exchange', publicRoutes, async (req: EnduranceRequest, res: Response, next: NextFunction) => {
      try {
        if (!this.authMiddleware?.auth) {
          throw new Error('Auth middleware not initialized');
        }
        await this.authMiddleware.auth.generateAzureTokens(req, res, next);
      } catch (error) {
        if (!res.headersSent) {
          next(error);
        } else {
          console.error('Error after headers sent:', error);
        }
      }
    });
  }
}

const userRouter = new UserRouter();
export default userRouter;
