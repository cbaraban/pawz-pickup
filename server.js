// server.js - Node.js Express Backend with Twilio & PostgreSQL
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const twilio = require('twilio');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware
app.use(helmet());
app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:3001',
    credentials: true
}));
app.use(express.json());

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// SMS rate limiting (more restrictive)
const smsLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 2, // limit each IP to 2 SMS requests per minute
    message: 'Too many SMS requests, please try again later'
});

// Database connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Twilio client
const twilioClient = twilio(
    process.env.TWILIO_ACCOUNT_SID,
    process.env.TWILIO_AUTH_TOKEN
);

// Database schema initialization
const initDatabase = async () => {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS customers (
                id SERIAL PRIMARY KEY,
                phone VARCHAR(20) UNIQUE NOT NULL,
                name VARCHAR(100),
                vehicle VARCHAR(100),
                is_verified BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS pets (
                id SERIAL PRIMARY KEY,
                customer_id INTEGER REFERENCES customers(id) ON DELETE CASCADE,
                name VARCHAR(50) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS verification_codes (
                id SERIAL PRIMARY KEY,
                phone VARCHAR(20) NOT NULL,
                code VARCHAR(6) NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                used BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS pickups (
                id SERIAL PRIMARY KEY,
                customer_id INTEGER REFERENCES customers(id) ON DELETE CASCADE,
                pets JSONB NOT NULL,
                service_type VARCHAR(20) NOT NULL,
                eta_minutes INTEGER NOT NULL,
                eta_time TIMESTAMP NOT NULL,
                stall_number INTEGER,
                status VARCHAR(20) DEFAULT 'expected',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP
            );

            CREATE INDEX IF NOT EXISTS idx_pickups_status ON pickups(status);
            CREATE INDEX IF NOT EXISTS idx_pickups_eta ON pickups(eta_time);
            CREATE INDEX IF NOT EXISTS idx_verification_phone ON verification_codes(phone);
        `);
        console.log('Database initialized successfully');
    } catch (error) {
        console.error('Database initialization error:', error);
    }
};

// Utility functions
const generateVerificationCode = () => {
    return Math.floor(100000 + Math.random() * 900000).toString();
};

const formatPhoneNumber = (phone) => {
    // Remove all non-digits and add +1 for US numbers
    const digits = phone.replace(/\D/g, '');
    return digits.startsWith('1') ? `+${digits}` : `+1${digits}`;
};

// Validation middleware
const validatePhone = [
    body('phone').isMobilePhone('en-US').withMessage('Invalid phone number format')
];

const validateCustomerInfo = [
    body('name').trim().isLength({ min: 1, max: 100 }).withMessage('Name is required'),
    body('vehicle').trim().isLength({ min: 1, max: 100 }).withMessage('Vehicle info is required'),
    body('pets').isArray({ min: 1 }).withMessage('At least one pet is required')
];

const validatePickupRequest = [
    body('pets').isArray({ min: 1 }).withMessage('At least one pet is required'),
    body('serviceType').isIn(['daycare', 'boarding', 'grooming']).withMessage('Invalid service type'),
    body('etaMinutes').isInt({ min: 5, max: 60 }).withMessage('ETA must be between 5-60 minutes')
];

// API Routes

// Send verification code
app.post('/api/send-verification', smsLimiter, validatePhone, async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { phone } = req.body;
        const formattedPhone = formatPhoneNumber(phone);
        const code = generateVerificationCode();
        const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

        // Clean up old codes for this phone
        await pool.query(
            'DELETE FROM verification_codes WHERE phone = $1 OR expires_at < NOW()',
            [formattedPhone]
        );

        // Store new verification code
        await pool.query(
            'INSERT INTO verification_codes (phone, code, expires_at) VALUES ($1, $2, $3)',
            [formattedPhone, code, expiresAt]
        );

        // Send SMS via Twilio
        await twilioClient.messages.create({
            body: `🐾 Your Pawz Pet Pickup verification code is: ${code}. This code expires in 10 minutes.`,
            from: process.env.TWILIO_PHONE_NUMBER,
            to: formattedPhone
        });

        res.json({ 
            success: true, 
            message: 'Verification code sent successfully',
            phone: formattedPhone 
        });

    } catch (error) {
        console.error('SMS sending error:', error);
        res.status(500).json({ 
            error: 'Failed to send verification code',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// Verify code and get/create customer
app.post('/api/verify-code', async (req, res) => {
    try {
        const { phone, code } = req.body;
        const formattedPhone = formatPhoneNumber(phone);

        // Check verification code
        const verificationResult = await pool.query(
            'SELECT * FROM verification_codes WHERE phone = $1 AND code = $2 AND expires_at > NOW() AND used = FALSE',
            [formattedPhone, code]
        );

        if (verificationResult.rows.length === 0) {
            return res.status(400).json({ error: 'Invalid or expired verification code' });
        }

        // Mark code as used
        await pool.query(
            'UPDATE verification_codes SET used = TRUE WHERE id = $1',
            [verificationResult.rows[0].id]
        );

        // Get or create customer
        let customer = await pool.query(
            'SELECT * FROM customers WHERE phone = $1',
            [formattedPhone]
        );

        if (customer.rows.length === 0) {
            // Create new customer
            customer = await pool.query(
                'INSERT INTO customers (phone, is_verified) VALUES ($1, TRUE) RETURNING *',
                [formattedPhone]
            );
        } else {
            // Update verification status
            await pool.query(
                'UPDATE customers SET is_verified = TRUE WHERE phone = $1',
                [formattedPhone]
            );
        }

        // Get customer's pets
        const pets = await pool.query(
            'SELECT name FROM pets WHERE customer_id = $1 ORDER BY created_at',
            [customer.rows[0].id]
        );

        // Generate JWT token
        const token = jwt.sign(
            { customerId: customer.rows[0].id, phone: formattedPhone },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            success: true,
            token,
            customer: {
                id: customer.rows[0].id,
                name: customer.rows[0].name,
                vehicle: customer.rows[0].vehicle,
                pets: pets.rows.map(p => p.name)
            }
        });

    } catch (error) {
        console.error('Verification error:', error);
        res.status(500).json({ error: 'Verification failed' });
    }
});

// JWT authentication middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid token' });
        }
        req.user = user;
        next();
    });
};

// Update customer info and pets
app.post('/api/customer/update', authenticateToken, validateCustomerInfo, async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { name, vehicle, pets } = req.body;
        const customerId = req.user.customerId;

        // Update customer info
        await pool.query(
            'UPDATE customers SET name = $1, vehicle = $2, updated_at = CURRENT_TIMESTAMP WHERE id = $3',
            [name, vehicle, customerId]
        );

        // Update pets (delete existing and insert new ones)
        await pool.query('DELETE FROM pets WHERE customer_id = $1', [customerId]);
        
        for (const petName of pets) {
            await pool.query(
                'INSERT INTO pets (customer_id, name) VALUES ($1, $2)',
                [customerId, petName.trim()]
            );
        }

        res.json({ success: true, message: 'Customer information updated' });

    } catch (error) {
        console.error('Customer update error:', error);
        res.status(500).json({ error: 'Failed to update customer information' });
    }
});

// Create pickup request
app.post('/api/pickup/create', authenticateToken, validatePickupRequest, async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { pets, serviceType, etaMinutes } = req.body;
        const customerId = req.user.customerId;
        const etaTime = new Date(Date.now() + etaMinutes * 60 * 1000);

        const result = await pool.query(
            'INSERT INTO pickups (customer_id, pets, service_type, eta_minutes, eta_time) VALUES ($1, $2, $3, $4, $5) RETURNING id',
            [customerId, JSON.stringify(pets), serviceType, etaMinutes, etaTime]
        );

        res.json({ 
            success: true, 
            pickupId: result.rows[0].id,
            message: 'Pickup request created successfully' 
        });

    } catch (error) {
        console.error('Pickup creation error:', error);
        res.status(500).json({ error: 'Failed to create pickup request' });
    }
});

// Update pickup with stall
app.post('/api/pickup/:id/stall', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { stallNumber } = req.body;
        const customerId = req.user.customerId;

        // Check if stall is available
        const occupiedStalls = await pool.query(
            'SELECT stall_number FROM pickups WHERE stall_number IS NOT NULL AND status != \'completed\' AND DATE(created_at) = CURRENT_DATE'
        );

        const occupied = occupiedStalls.rows.map(row => row.stall_number);
        if (occupied.includes(stallNumber)) {
            return res.status(400).json({ error: 'Stall is already occupied' });
        }

        // Update pickup with stall
        await pool.query(
            'UPDATE pickups SET stall_number = $1, status = \'arrived\' WHERE id = $2 AND customer_id = $3',
            [stallNumber, id, customerId]
        );

        res.json({ success: true, message: 'Stall updated successfully' });

    } catch (error) {
        console.error('Stall update error:', error);
        res.status(500).json({ error: 'Failed to update stall' });
    }
});

// Get available stalls
app.get('/api/stalls/available', async (req, res) => {
    try {
        const occupiedStalls = await pool.query(
            'SELECT stall_number FROM pickups WHERE stall_number IS NOT NULL AND status != \'completed\' AND DATE(created_at) = CURRENT_DATE'
        );

        const occupied = occupiedStalls.rows.map(row => row.stall_number);
        const available = [1, 2, 3, 4, 5].filter(stall => !occupied.includes(stall));

        res.json({ available, occupied });

    } catch (error) {
        console.error('Stalls query error:', error);
        res.status(500).json({ error: 'Failed to get stall availability' });
    }
});

// Get current pickups for staff dashboard
app.get('/api/pickups/current', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                p.id,
                p.pets,
                p.service_type,
                p.eta_time,
                p.stall_number,
                p.status,
                p.created_at,
                c.name as customer_name,
                c.phone,
                c.vehicle
            FROM pickups p
            JOIN customers c ON p.customer_id = c.id
            WHERE p.status != 'completed' AND DATE(p.created_at) = CURRENT_DATE
            ORDER BY p.eta_time ASC
        `);

        // Check for late pickups
        const now = new Date();
        const pickups = result.rows.map(pickup => {
            const isLate = pickup.status === 'expected' && 
                          new Date(pickup.eta_time).getTime() < (now.getTime() - 5 * 60 * 1000);
            
            return {
                ...pickup,
                status: isLate ? 'late' : pickup.status,
                pets: pickup.pets
            };
        });

        // Update late pickups in database
        const latePickups = pickups.filter(p => p.status === 'late');
        for (const pickup of latePickups) {
            await pool.query(
                'UPDATE pickups SET status = \'late\' WHERE id = $1',
                [pickup.id]
            );
        }

        res.json(pickups);

    } catch (error) {
        console.error('Pickups query error:', error);
        res.status(500).json({ error: 'Failed to get current pickups' });
    }
});

// Complete pickup (staff only)
app.post('/api/pickup/:id/complete', async (req, res) => {
    try {
        const { id } = req.params;
        
        await pool.query(
            'UPDATE pickups SET status = \'completed\', completed_at = CURRENT_TIMESTAMP WHERE id = $1',
            [id]
        );

        res.json({ success: true, message: 'Pickup marked as completed' });

    } catch (error) {
        console.error('Pickup completion error:', error);
        res.status(500).json({ error: 'Failed to complete pickup' });
    }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'healthy', 
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV
    });
});

// Cleanup old data (run daily)
const cleanupOldData = async () => {
    try {
        // Delete completed pickups older than 24 hours
        await pool.query(
            'DELETE FROM pickups WHERE status = \'completed\' AND completed_at < NOW() - INTERVAL \'24 hours\''
        );
        
        // Delete expired verification codes
        await pool.query(
            'DELETE FROM verification_codes WHERE expires_at < NOW()'
        );
        
        console.log('Daily cleanup completed');
    } catch (error) {
        console.error('Cleanup error:', error);
    }
};

// Schedule daily cleanup at midnight
const scheduleCleanup = () => {
    const now = new Date();
    const midnight = new Date();
    midnight.setHours(24, 0, 0, 0);
    
    const timeUntilMidnight = midnight - now;
    
    setTimeout(() => {
        cleanupOldData();
        setInterval(cleanupOldData, 24 * 60 * 60 * 1000); // Run daily
    }, timeUntilMidnight);
};

// Error handling middleware
app.use((error, req, res, next) => {
    console.error('Unhandled error:', error);
    res.status(500).json({ 
        error: 'Internal server error',
        details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
});

// Start server
const startServer = async () => {
    try {
        await initDatabase();
        scheduleCleanup();
        
        app.listen(PORT, () => {
            console.log(`🐾 Pawz Pet Pickup Server running on port ${PORT}`);
            console.log(`Environment: ${process.env.NODE_ENV}`);
        });
    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
};

startServer();
