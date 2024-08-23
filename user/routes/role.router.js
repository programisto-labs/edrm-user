const express = require('express');
const Role = require('../models/role.model');
const { checkUserPermissions } = require('../middlewares/auth.middleware');
const auth = require('endurance-core/lib/auth');
const router = require('endurance-core/lib/router')();

const checkSuperAdmin = checkUserPermissions([], true); // Utilisation du middleware

router.autoWire(Role, 'Role');

router.post('/:roleId/assign-permissions', checkSuperAdmin, auth.asyncHandler(async (req, res) => {
  const { roleId } = req.params;
  const { permissions } = req.body;

  const role = await Role.findById(roleId);
  if (!role) {
    return res.status(404).json({ message: 'Role not found' });
  }

  role.permissions = permissions;
  await role.save();

  res.json({ message: 'Permissions assigned successfully', role });
}));

module.exports = router;
