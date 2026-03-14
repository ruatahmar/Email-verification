/**
 * Main entry point for the backend application
 * Express server with authentication system integration
 */
// Initialize logging and verification workers
require('./functions/logging/logger');
require('./functions/staging/queue');
require('./functions/verifier/controller');
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const path = require('path');
const { validateEnvironment, PORT, SESSION_SECRET, SESSION_MAX_AGE, DB_PATH } = require('./data/env');
const { initializeDatabase } = require('./database/connection');
const { helmetConfig, corsConfig } = require('./functions/middleware/security');
const passport = require('./functions/middleware/passport');
const authRoutes = require('./routes/api/auth-simple');
const verifierRoutes = require('./routes/api/verifier');
const apiKeysRoutes = require('./routes/api/api-keys');

// Validate environment variables on startup
validateEnvironment();

// Server configuration
const port = PORT;
const app = express();

// Initialize database on startup

/**
 * Initialize database and create tables
 * @returns {void}
 */
function initializeApp() {
	try {
		// Initialize database connection and create tables
		initializeDatabase();
		console.log('Database initialization completed');
	} catch (error) {
		const errorMessage = error instanceof Error ? error.message : String(error);
		console.error('App initialization failed:', errorMessage);
		throw error;
	} finally {
		console.debug('App initialization process completed');
	}
}

// Apply global middleware

/**
 * Setup middleware for the Express application
 * @returns {void}
 */
function setupMiddleware() {
	try {
		// Trust proxy - set to 1 for single proxy (more secure than true)
		// If behind multiple proxies, set to the number of proxies
		app.set('trust proxy', 1);

		// Security headers
		app.use(helmetConfig);

		// CORS configuration
		app.use(corsConfig);

		// Note: Rate limiting is now applied per-route basis for sensitive endpoints only

		// Body parsing middleware
		app.use(express.json({ limit: '10mb' }));
		app.use(express.urlencoded({ extended: true, limit: '10mb' }));

		// Session middleware
		app.use(
			session({
				store: new SQLiteStore({
					db: 'sessions.db',
					dir: path.dirname(DB_PATH),
				}),
				secret: SESSION_SECRET,
				resave: false,
				saveUninitialized: false,
				name: 'connect.sid',
				cookie: {
					maxAge: SESSION_MAX_AGE,
					httpOnly: true,
					secure: false, // Set to false for local development (even if served over HTTP)
					sameSite: 'lax',
					path: '/',
				},
			})
		);

		// Passport authentication middleware
		app.use(passport.initialize());
		app.use(passport.session());

		// Serve static files from the frontend build
		app.use(express.static(path.join(__dirname, 'public')));
		app.use('/fast', express.static(path.join(__dirname, 'public')));
		// Request logging middleware
		app.use((req, res, next) => {
			console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
			next();
		});

		console.log('Middleware setup completed');
	} catch (error) {
		const errorMessage = error instanceof Error ? error.message : String(error);
		console.error('Middleware setup failed:', errorMessage);
		throw error;
	} finally {
		console.debug('Middleware setup process completed');
	}
}

// Setup API routes

/**
 * Configure API routes
 * @returns {void}
 */
function setupRoutes() {
	try {
		// Authentication routes (simple, no database)
		app.use('/api/auth', authRoutes);

		// Verifier routes
		app.use('/api/verifier', verifierRoutes);

		// API Keys routes
		app.use('/api/api-keys', apiKeysRoutes);

		// API health check
		app.get('/api/health', (req, res) => {
			res.json({
				success: true,
				message: 'API is healthy',
				services: {
					database: 'connected',
					authentication: 'active',
					settings: 'active',
					verifier: 'active',
					apiKeys: 'active',
				},
				timestamp: new Date().toISOString(),
			});
		});

		// 404 handler for unknown API routes, SPA fallback for all others
		app.use((req, res) => {
			if (req.path.startsWith('/api/')) {
				res.status(404).json({
					success: false,
					message: 'API endpoint not found',
					path: req.originalUrl,
				});
			} else {
				// SPA fallback - serve index.html for all non-API routes
				// res.sendFile(path.join(__dirname, 'public', 'index.html'));
				if (req.path.startsWith('/fast/') || !req.path.startsWith('/api/')) {
					res.sendFile(path.join(__dirname, 'public', 'index.html'));
				}
			}
		});

		console.log('Routes setup completed');
	} catch (error) {
		const errorMessage = error instanceof Error ? error.message : String(error);
		console.error('Routes setup failed:', errorMessage);
		throw error;
	} finally {
		console.debug('Routes setup process completed');
	}
}

// Global error handler

/**
 * Setup global error handling middleware
 * @returns {void}
 */
function setupErrorHandler() {
	try {
		app.use((error, req, res, next) => {
			const errorMessage = error instanceof Error ? error.message : String(error);
			console.error('Global error:', errorMessage);

			res.status(500).json({
				success: false,
				message: 'Internal server error',
				timestamp: new Date().toISOString(),
			});
		});

		console.log('Error handler setup completed');
	} catch (error) {
		const errorMessage = error instanceof Error ? error.message : String(error);
		console.error('Error handler setup failed:', errorMessage);
		throw error;
	} finally {
		console.debug('Error handler setup process completed');
	}
}

// Start server function with proper error handling

/**
 * Start the Express server
 * @returns {void}
 */
function startServer() {
	try {
		// Initialize application components
		initializeApp();
		setupMiddleware();
		setupRoutes();
		setupErrorHandler();

		// Start the server
		app.listen(port, () => {
			console.log(`\n🚀 Server is running on port ${port}`);
			console.log(`🎞️ Frontend is running on: http://localhost:${port}`);
			console.log(`📚 API Documentation: http://localhost:${port}/api/health`);
			console.log(`🔐 Authentication API: http://localhost:${port}/api/auth/health`);
			console.log(`⚙️  Settings API: http://localhost:${port}/api/settings/health`);
			console.log(`📧 Verifier API: http://localhost:${port}/api/verifier/health`);
			console.log(`🔑 API Keys API: http://localhost:${port}/api/api-keys`);
			console.log(`⚡ Environment: ${process.env.NODE_ENV || 'development'}\n`);
		});
	} catch (error) {
		const errorMessage = error instanceof Error ? error.message : String(error);
		console.error('Server startup failed:', errorMessage);
		throw error;
	} finally {
		console.debug('Server startup process completed');
	}
}

// Graceful shutdown handling

/**
 * Handle graceful shutdown
 * @returns {void}
 */
function setupGracefulShutdown() {
	try {
		process.on('SIGTERM', () => {
			console.log('SIGTERM received, shutting down gracefully');
			process.exit(0);
		});

		process.on('SIGINT', () => {
			console.log('SIGINT received, shutting down gracefully');
			process.exit(0);
		});
	} catch (error) {
		const errorMessage = error instanceof Error ? error.message : String(error);
		console.error('Graceful shutdown setup failed:', errorMessage);
		throw error;
	} finally {
		console.debug('Graceful shutdown setup process completed');
	}
}

// Initialize graceful shutdown and start the server
setupGracefulShutdown();
startServer();
