import router from 'endurance-core/lib/router.js';
import auth from 'endurance-core/lib/auth.js';
import { emitter, eventTypes } from 'endurance-core/lib/emitter.js';
import User from '../models/user.model.js';
import Role from '../models/role.model.js';

const userRouter = router();


userRouter.get('/auth-methods', async (req, res) => {
  const authMethods = {
    local: process.env.LOGIN_LOCAL_ACTIVATED === 'true',
    azure: process.env.LOGIN_AZURE_ACTIVATED === 'true'
  };
  res.json({ authMethods });
});

userRouter.get('/check-auth', auth.authenticateJwt(), async (req, res) => {
  res.json({ result: 'ok' });
});

userRouter.post('/register', async (req, res) => {
  const user = new User(req.body);
  await user.save();
  emitter.emit(eventTypes.userRegistered, user);
  res.status(201).json({ message: 'User registered successfully' });
});

if(process.env.LOGIN_LOCAL_ACTIVATED){
  userRouter.post('/login/local', auth.authenticateLocalAndGenerateTokens(), (req, res) => {
    emitter.emit(eventTypes.userLoggedIn, req.user);
    res.json({ message: 'User logged in successfully' });
  });

  userRouter.post('/request-password-reset',async (req, res) => {
    const { email } = req.body;
    const user = await User.findOne({ email });
  
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
  
    const resetToken = auth.generateToken({ id: user._id }, '10m');
    user.resetToken = resetToken;
    user.resetTokenExpiration = Date.now() + 10 * 60 * 1000; // 10 minutes from now
    await user.save();
  
    // Emit an event or send an email with the reset token
    emitter.emit('passwordResetRequested', { user, resetToken });
  
    res.json({ message: 'Password reset token generated', resetToken });
  });
  
  userRouter.post('/reset-password', async (req, res) => {
    const { resetToken, newPassword } = req.body;
    const user = await User.findOne({ resetToken, resetTokenExpiration: { $gt: Date.now() } });
  
    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired reset token' });
    }
  
    user.password = newPassword;
    user.resetToken = null;
    user.resetTokenExpiration = null;
    await user.save();
  
    emitter.emit('passwordReset', user);
  
    res.json({ message: 'Password has been reset successfully' });
  });
}

if (process.env.LOGIN_AZURE_ACTIVATED === 'true') {

  if (!process.env.AZURE_CLIENT_ID ||
    !process.env.AZURE_CLIENT_SECRET ||
    !process.env.AZURE_RESOURCE ||
    !process.env.AZURE_TENANT ||
    !process.env.AZURE_CALLBACK_URL) {
    console.error('Error: Azure environment variables are not set. Azure login routes will not be loaded.');
  } else {

    userRouter.get('/login/azure', auth.authenticateAzureAndGenerateTokens(), (req, res) => {
      emitter.emit(eventTypes.userLoggedIn, req.user);
      const loginCallbackUrl = process.env.AZURE_CALLBACK_URL;
      if (loginCallbackUrl) {
        return res.redirect(loginCallbackUrl);
      } else {
        res.json({ message: 'User logged in successfully' });
      }
    });

    userRouter.post('/login/azure/exchange', auth.generateAzureTokens(), (req, res) => {
      emitter.emit(eventTypes.userLoggedIn, req.user);

      res.json({ message: 'User logged in successfully' });

    });
  }
}

userRouter.get('/profile', auth.restrictToOwner((req) => req.user.id), (req, res) => {
  res.json(req.user);
});

userRouter.patch('/profile', auth.restrictToOwner((req) => req.user.id), auth.asyncHandler(async (req, res) => {
  const allowedUpdates = ['name', 'email', 'password'];
  const updates = Object.keys(req.body);

  const isValidOperation = updates.every(update => allowedUpdates.includes(update));

  if (!isValidOperation) {
    return res.status(400).json({ message: 'Invalid updates!' });
  }

  updates.forEach(update => req.user[update] = req.body[update]);

  if (req.body.password) {
    req.user.password = req.body.password;
  }

  await req.user.save();
  emitter.emit(eventTypes.userProfileUpdated, req.user);
  res.json(req.user);
}));

userRouter.delete('/profile', auth.checkUserPermissions(['canDeleteUser']), auth.asyncHandler(async (req, res) => {
  await req.user.remove();
  emitter.emit('userDeleted', req.user);
  res.json({ message: 'User deleted successfully' });
}));

userRouter.post('/assign-role',
  auth.authenticateJwt(),
  auth.checkUserPermissions(['canAssignRoles'], true),
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
    emitter.emit(eventTypes.roleAssigned, { user, role });
    res.json({ message: 'Role assigned successfully', user });
  }));

userRouter.post('/refresh-token', auth.refreshJwt());

userRouter.post('/revoke-token', auth.revokeRefreshToken());

export default userRouter;
