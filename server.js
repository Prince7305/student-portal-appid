// server.js
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));

// Session setup
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production', // HTTPS only in prod
    httpOnly: true,
    sameSite: 'lax'
  }
}));

app.use(passport.initialize());
app.use(passport.session());

// Simple serialize/deserialize
passport.serializeUser ((user, done) => {
  console.log('Serializing user:', user); // Debug log
  done(null, user);
});
passport.deserializeUser ((obj, done) => {
  console.log('Deserializing user:', obj); // Debug log
  done(null, obj);
});

// Determine if IBM App ID config is present
const hasAppId = !!(
  process.env.OAUTH_SERVER_URL &&
  process.env.CLIENT_ID &&
  process.env.SECRET &&
  process.env.REDIRECT_URI &&
  process.env.TENANT_ID
);

if (hasAppId) {
  const { WebAppStrategy } = require('ibmcloud-appid');

  passport.use('appid', new WebAppStrategy({
    tenantId: process.env.TENANT_ID,
    clientId: process.env.CLIENT_ID,
    secret: process.env.SECRET,
    oauthServerUrl: process.env.OAUTH_SERVER_URL,
    redirectUri: process.env.REDIRECT_URI
  }, (tokens, profile, done) => {
    console.log('Verify callback: tokens exist?', !!tokens, 'profile:', profile); // Debug log
    const user = { profile };
    return done(null, user);
  }));

  console.log('Using IBM App ID authentication (WebAppStrategy)');
} else {
  console.log('IBM App ID not configured. Using local dev fallback (no external auth).');
}

// Middleware: ensure user has a role
function ensureRole(role) {
  return (req, res, next) => {
    const isAuth = hasAppId ? req.isAuthenticated() : !!req.session.role;
    const hasCorrectRole = req.session.role === role;
    console.log(`ensureRole debug for ${role}: isAuthenticated=${isAuth}, session.role=${req.session.role}, required=${role}, user=${req.user ? 'exists' : 'null'}`); // Debug log
    if ((hasAppId ? (isAuth && hasCorrectRole) : hasCorrectRole)) {
      return next();
    }
    console.log(`Access denied for ${role}: auth=${isAuth}, role match=${hasCorrectRole}`); // Debug log
    res.status(403).send(`<h1>Access Denied</h1><p>Only ${role} can access this page.</p><a href="/">Go to Home</a>`);
  };
}

// Routes
app.get('/', (req, res) => {
  console.log('Home page accessed, authenticated?', req.isAuthenticated(), 'role?', req.session.role); // Debug log
  res.sendFile(path.join(__dirname, 'views', 'index.html'));
});

// Start auth flow for chosen role
app.get('/auth/:role', (req, res, next) => {
  const role = req.params.role;
  console.log(`Auth request for role: ${role}, current session roleChoice: ${req.session.roleChoice}`); // Debug log
  if (!['student', 'admin'].includes(role)) {
    return res.status(400).send('Invalid role');
  }

  // Save chosen role in session before redirecting to auth
  req.session.roleChoice = role;
  console.log(`Set roleChoice to: ${role}`); // Debug log

  if (hasAppId) {
    // Persist session to ensure roleChoice survives the external redirect to App ID
    return req.session.save((saveErr) => {
      if (saveErr) {
        console.error('Session save error in /auth:', saveErr); // Debug log
        return next(saveErr);
      }
      console.log('Session saved before App ID redirect, roleChoice:', req.session.roleChoice); // Debug log
      return passport.authenticate('appid', {})(req, res, next);
    });
  } else {
    // Dev fallback – fake login
    console.log('Dev mode: Logging in with role', role); // Debug log
    req.logIn({ dev: true, role: role }, (err) => {
      if (err) {
        console.error('Dev login error:', err); // Debug log
        return next(err);
      }
      req.session.role = role; // Set role directly
      console.log('Dev login complete, redirecting to', role === 'admin' ? '/admin' : '/dashboard'); // Debug log
      return res.redirect(role === 'admin' ? '/admin' : '/dashboard');
    });
  }
});

// App ID callback
app.get('/callback', (req, res, next) => {
  if (!hasAppId) return res.redirect('/');
  console.log('Callback accessed, current session roleChoice:', req.session.roleChoice, 'isAuthenticated?', req.isAuthenticated()); // Debug log

  passport.authenticate('appid', { failureRedirect: '/', keepSessionInfo: true }, (err, user) => {
    console.log('Auth callback: err?', err, 'user?', !!user, 'user details:', user); // Debug log
    if (err) {
      console.error('Auth error in callback:', err); // Debug log
      return next(err);
    }
    if (!user) {
      console.log('No user from auth, redirecting to /'); // Debug log
      return res.redirect('/');
    }

    // Restore role choice from session BEFORE logging in
    const role = req.session.roleChoice || 'student';
    console.log('Restoring role from session:', role, 'roleChoice was:', req.session.roleChoice); // Debug log
    delete req.session.roleChoice;
    req.session.role = role;

    req.logIn(user, { keepSessionInfo: true }, (loginErr) => {
      if (loginErr) {
        console.error('Login error after auth:', loginErr); // Debug log
        return next(loginErr);
      }
      console.log('Login successful, isAuthenticated now?', req.isAuthenticated(), 'session.role:', req.session.role, 'user:', req.user); // Debug log
      const redirectTo = role === 'admin' ? '/admin' : '/dashboard';
      console.log('Redirecting to:', redirectTo); // Debug log
      return res.redirect(redirectTo);
    });
  })(req, res, next);
});

// Protected pages
app.get('/dashboard', ensureRole('student'), (req, res) => {
  console.log('Dashboard accessed successfully'); // Debug log
  res.sendFile(path.join(__dirname, 'views', 'dashboard.html'));
});

app.get('/admin', ensureRole('admin'), (req, res) => {
  console.log('Admin accessed successfully'); // Debug log
  res.sendFile(path.join(__dirname, 'views', 'admin.html'));
});

// Logout
app.get('/logout', (req, res, next) => {
  console.log('Logout requested, was authenticated?', req.isAuthenticated()); // Debug log
  req.logout((err) => {
    if (err) {
      console.error('Logout error:', err); // Debug log
      return next(err);
    }
    req.session.destroy((destroyErr) => {
      if (destroyErr) console.error('Session destroy error:', destroyErr); // Debug log
      res.redirect('/');
    });
  });
});

// Health check
app.get('/health', (req, res) => {
  res.json({ ok: true, authenticated: req.isAuthenticated(), role: req.session.role });
});

// Error handlers
process.on('uncaughtException', (err) => {
  console.error('Uncaught exception:', err);
  process.exit(1);
});
process.on('unhandledRejection', (reason) => {
  console.error('Unhandled Rejection:', reason);
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
