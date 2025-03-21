import { EnduranceRouter, Request as BaseRequest, Response, type SecurityOptions } from 'endurance-core';
import { enduranceEmitter as emitter, enduranceEventTypes as eventTypes } from 'endurance-core';
import User from '../models/user.model.js';
import Role from '../models/role.model.js';
import authMiddleware from '../middlewares/auth.middleware.js';

interface Request extends BaseRequest {
  user?: InstanceType<typeof User> & { password?: string; save(): Promise<any>; remove(): Promise<void>; };
}

class UserRouter extends EnduranceRouter {
  constructor() {
    super(authMiddleware);
  }

  setupRoutes(): void {
    const publicRoutes: SecurityOptions = {
      requireAuth: false
    };

    const authenticatedRoutes: SecurityOptions = {
      requireAuth: true
    };

    this.get('/test', publicRoutes, (req, res) => {
      this.checkAuth(req, res);
    });

    // Routes publiques
    this.get('/auth-methods', publicRoutes, (req, res) => { this.getAuthMethods(req, res); });
    this.get('/find', publicRoutes, (req, res) => { this.findUser(req, res); });
    this.post('/register', publicRoutes, (req, res) => { this.registerUser(req, res); });

    // Routes authentifiées
    this.get('/check-auth', authenticatedRoutes, (req, res) => { this.checkAuth(req, res); });

    if (process.env.LOGIN_LOCAL_ACTIVATED) {
      this.post('/login/local', publicRoutes, (req, res) => { this.localLogin(req, res); });
      this.post('/request-password-reset', publicRoutes, (req, res) => { this.requestPasswordReset(req, res); });
      this.post('/reset-password', publicRoutes, (req, res) => { this.resetPassword(req, res); });
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

    this.get('/profile', profileRoutes, (req, res) => { this.getProfile(req, res); });
    this.patch('/profile', profileRoutes, (req, res) => { this.updateProfile(req, res); });
    this.delete('/profile', adminRoutes, (req, res) => { this.deleteProfile(req, res); });
    this.post('/assign-role', adminRoutes, (req, res) => { this.assignRole(req, res); });
    this.post('/refresh-token', authenticatedRoutes, (req, res) => { this.refreshToken(req, res); });
    this.post('/revoke-token', authenticatedRoutes, (req, res) => { this.revokeToken(req, res); });
  }

  private getAuthMethods = async (req: Request, res: Response): Promise<void> => {
    const authMethods = {
      local: process.env.LOGIN_LOCAL_ACTIVATED === 'true',
      azure: process.env.LOGIN_AZURE_ACTIVATED === 'true'
    };
    res.json({ authMethods });
  };

  private checkAuth = async (req: Request, res: Response): Promise<void> => {
    res.json({ result: 'ok' });
  };

  private findUser = async (req: Request, res: Response): Promise<void> => {
    const { email } = req.query;
    const user = await User.findOne({ email });
    res.json(user);
  };

  private registerUser = async (req: Request, res: Response): Promise<void> => {
    const user = new User(req.body);
    await user.save();
    emitter.emit(eventTypes.userRegistered, user);
    res.status(201).json({ message: 'User registered successfully' });
  };

  private localLogin = async (req: Request, res: Response): Promise<void> => {
    emitter.emit(eventTypes.userLoggedIn, req.user);
    res.json({ message: 'User logged in successfully' });
  };

  private requestPasswordReset = async (req: Request, res: Response): Promise<void> => {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      res.status(404).json({ message: 'User not found' });
      return;
    }

    const resetToken = await authMiddleware.auth.generateToken({ id: user._id });
    user.resetToken = resetToken;
    user.resetTokenExpiration = Date.now() + 10 * 60 * 1000; // 10 minutes from now
    await user.save();

    emitter.emit('passwordResetRequested', { user, resetToken });

    res.json({ message: 'Password reset token generated' });
  };

  private resetPassword = async (req: Request, res: Response): Promise<void> => {
    const { resetToken, newPassword } = req.body;
    const user = await User.findOne({ resetToken, resetTokenExpiration: { $gt: Date.now() } });

    if (!user) {
      res.status(400).json({ message: 'Invalid or expired reset token' });
      return;
    }

    user.password = newPassword;
    user.resetToken = null;
    user.resetTokenExpiration = null;
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

      this.get('/login/azure', publicRoutes, (req, res) => { this.azureLogin(req, res); });
      this.post('/login/azure/exchange', publicRoutes, (req, res) => { this.azureExchange(req, res); });
    }
  }

  private azureLogin = async (req: Request, res: Response): Promise<void> => {
    emitter.emit(eventTypes.userLoggedIn, req.user);
    const loginCallbackUrl = process.env.AZURE_CALLBACK_URL;
    if (loginCallbackUrl) {
      return res.redirect(loginCallbackUrl);
    }
    res.json({ message: 'User logged in successfully' });
  };

  private azureExchange = async (req: Request, res: Response) => {
    emitter.emit(eventTypes.userLoggedIn, req.user);
    res.json({ message: 'User logged in successfully' });
  };

  private getProfile = async (req: Request, res: Response): Promise<void> => {
    res.json(req.user);
  };

  private updateProfile = async (req: Request, res: Response): Promise<void> => {
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

  private deleteProfile = async (req: Request, res: Response): Promise<void> => {
    await req.user.remove();
    emitter.emit('userDeleted', req.user);
    res.json({ message: 'User deleted successfully' });
  };

  private assignRole = async (req: Request, res: Response): Promise<void> => {
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

  private refreshToken = async (req: Request, res: Response) => {
    res.json({ message: 'Token refreshed successfully' });
  };

  private revokeToken = async (req: Request, res: Response) => {
    res.json({ message: 'Token revoked successfully' });
  };
}

const userRouter = new UserRouter();
export default userRouter;
