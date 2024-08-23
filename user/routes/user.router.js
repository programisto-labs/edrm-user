const router = require('endurance-core/lib/router')();
const auth = require('endurance-core/lib/auth');
const { checkUserPermissions, restrictToOwner } = require('../middlewares/auth.middleware');
const User = require('../models/user.model');
const Role = require('../models/role.model');

router.post('/register', auth.asyncHandler(async (req, res) => {
  const user = new User(req.body);
  await user.save();
  res.status(201).json({ message: 'User registered successfully' });
}));

router.post('/login', auth.authenticateAndGenerateTokens());

router.get('/profile', restrictToOwner((req) => req.user.id), (req, res) => {
  res.json(req.user);
});

router.patch('/profile', restrictToOwner((req) => req.user.id), auth.asyncHandler(async (req, res) => {
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
  res.json(req.user);
}));

router.delete('/profile', checkUserPermissions(['canDeleteUser']), auth.asyncHandler(async (req, res) => {
  await req.user.remove();
  res.json({ message: 'User deleted successfully' });
}));

router.post('/assign-role', 
  auth.authenticateJWT(), 
  checkUserPermissions(['canAssignRoles'], true),  
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

router.post('/refresh-token', auth.refreshJWT());

router.post('/revoke-token', auth.revokeRefreshToken());

module.exports = router;
