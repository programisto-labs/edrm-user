const express = require('express');
const Permission = require('../models/permission.model');
const auth = require('endurance-core/lib/auth');
const RouterBase = require('endurance-core/lib/router');

const router = RouterBase();

const checkSuperAdmin = auth.checkUserPermissions([], true); 

RouterBase.autoWire(router, Permission, 'Permission');

module.exports = router;
