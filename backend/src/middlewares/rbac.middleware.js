// Permission checks use every role assigned to the user (primary role + user_roles),
// loaded once per request by `authenticate`.

const denied = (res, permission) => res.status(403).json({ error: 'Permission denied', code: 'PERMISSION_DENIED', permission });

export const requirePermission = (key) => (req, res, next) => {
  if (!req.user?.permissions?.includes(key)) return denied(res, key);
  return next();
};

export const requireAnyPermission = (...keys) => (req, res, next) => {
  if (!keys.some((key) => req.user?.permissions?.includes(key))) return denied(res, keys.join(' | '));
  return next();
};
