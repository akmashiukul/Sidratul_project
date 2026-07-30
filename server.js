const express    = require('express');
const mysql      = require('mysql2');
const cors       = require('cors');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET  = 'hms_super_secret_key_2025';   // change this in production
const JWT_EXPIRES = '24h';

// ============================================================
// DATABASE POOL
// ============================================================
const db = mysql.createPool({
    host: 'localhost', user: 'root', password: '', database: 'hostel_management',
    waitForConnections: true, connectionLimit: 10, queueLimit: 0
});

db.getConnection((err, conn) => {
    if (err) { console.error('❌ DB connection failed:', err.message); return; }
    console.log('✅ Connected to MySQL via Pool.');

    // Auto-migrate schema updates if missing
    conn.query("SHOW COLUMNS FROM APPLICATION LIKE 'room_id'", (e1, rows) => {
        if (!e1 && rows.length === 0) {
            conn.query("ALTER TABLE APPLICATION ADD COLUMN room_id INT NULL AFTER student_id", () => {
                console.log('✅ Auto-added room_id column to APPLICATION table.');
            });
        }
    });

    conn.query("SHOW TABLES LIKE 'TECH_REPORT'", (e2, rows2) => {
        if (!e2 && rows2.length === 0) {
            conn.query(`CREATE TABLE TECH_REPORT (
                report_id INT NOT NULL AUTO_INCREMENT,
                admin_id INT NOT NULL,
                report_subject VARCHAR(255) NOT NULL,
                report_detail TEXT NOT NULL,
                report_status ENUM('Open','In Progress','Resolved') NOT NULL DEFAULT 'Open',
                created_at DATETIME DEFAULT NOW(),
                PRIMARY KEY (report_id),
                FOREIGN KEY (admin_id) REFERENCES ADMIN(admin_id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`, () => {
                console.log('✅ Auto-created TECH_REPORT table.');
            });
        }
    });

    conn.release();
});

// ============================================================
// AUTH MIDDLEWARE
// ============================================================
function protect(...roles) {
    return (req, res, next) => {
        const auth  = req.headers['authorization'];
        const token = auth && auth.startsWith('Bearer ') ? auth.slice(7) : null;
        if (!token) return res.status(401).json({ error: 'Not authenticated. Please log in.' });

        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            req.user = decoded;   // { user_id, role, linked_id, admin_id }
            if (roles.length && !roles.includes(decoded.role)) {
                return res.status(403).json({ error: 'Access denied — insufficient role.' });
            }
            next();
        } catch (e) {
            return res.status(401).json({ error: 'Session expired. Please log in again.' });
        }
    };
}

// Helper: get admin_id from token (admin sees own data; super_admin sees all or can pass ?admin_id)
function getAdminId(req) {
    if (req.user.role === 'super_admin') return req.query.admin_id || null;
    if (req.user.role === 'admin')       return req.user.linked_id;
    if (req.user.role === 'student')     return null;  // filtered by student_id instead
}

// ============================================================
// AUTH ROUTES
// ============================================================

// POST /api/auth/login  — all roles
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required.' });

    db.query('SELECT * FROM USERS WHERE email = ? AND is_active = 1', [email], async (err, rows) => {
        if (err)             return res.status(500).json({ error: err.message });
        if (!rows.length)    return res.status(401).json({ error: 'Invalid email or password.' });

        const user = rows[0];
        const ok   = await bcrypt.compare(password, user.password_hash);
        if (!ok)             return res.status(401).json({ error: 'Invalid email or password.' });

        const token = jwt.sign(
            { user_id: user.user_id, role: user.role, linked_id: user.linked_id },
            JWT_SECRET, { expiresIn: JWT_EXPIRES }
        );
        res.json({ token, role: user.role, name: user.name, linked_id: user.linked_id });
    });
});

// POST /api/auth/signup  — student self-registers
app.post('/api/auth/signup', async (req, res) => {
    const { student_name, department, phone, email, guardian_name, password, admin_id } = req.body;
    if (!email || !password || !student_name) return res.status(400).json({ error: 'Name, email and password are required.' });
    if (!admin_id) return res.status(400).json({ error: 'Please select your hostel / admin.' });

    const hash = await bcrypt.hash(password, 10);

    // Insert STUDENT first
    db.query(
        'INSERT INTO STUDENT (student_name, department, phone, email, guardian_name, admin_id) VALUES (?,?,?,?,?,?)',
        [student_name, department, phone, email, guardian_name, admin_id],
        (err, r) => {
            if (err) return res.status(500).json({ error: err.message.includes('Duplicate') ? 'Email already registered.' : err.message });
            const student_id = r.insertId;

            // Insert USERS login
            db.query(
                'INSERT INTO USERS (name, email, password_hash, role, linked_id) VALUES (?,?,?,?,?)',
                [student_name, email, hash, 'student', student_id],
                (err2) => {
                    if (err2) return res.status(500).json({ error: err2.message });
                    res.json({ success: true, message: 'Account created! You can now log in.' });
                }
            );
        }
    );
});

// POST /api/auth/create-admin  — super_admin only
app.post('/api/auth/create-admin', protect('super_admin'), async (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'Name, email and password required.' });

    const hash = await bcrypt.hash(password, 10);

    db.query('INSERT INTO ADMIN (admin_name, admin_email) VALUES (?,?)', [name, email], (err, r) => {
        if (err) return res.status(500).json({ error: err.message });
        const admin_id = r.insertId;

        db.query(
            'INSERT INTO USERS (name, email, password_hash, role, linked_id) VALUES (?,?,?,?,?)',
            [name, email, hash, 'admin', admin_id],
            (err2) => {
                if (err2) return res.status(500).json({ error: err2.message });
                res.json({ success: true, message: `Admin "${name}" created successfully.` });
            }
        );
    });
});

// POST /api/auth/create-student  — admin creates student with custom password
app.post('/api/auth/create-student', protect('admin', 'super_admin'), async (req, res) => {
    const { student_name, department, phone, email, guardian_name, password } = req.body;
    if (!student_name || !email || !password) return res.status(400).json({ error: 'Name, email and password required.' });

    const admin_id = req.user.role === 'admin' ? req.user.linked_id : req.body.admin_id;
    const hash     = await bcrypt.hash(password, 10);

    db.query(
        'INSERT INTO STUDENT (student_name, department, phone, email, guardian_name, admin_id) VALUES (?,?,?,?,?,?)',
        [student_name, department, phone, email, guardian_name, admin_id],
        (err, r) => {
            if (err) return res.status(500).json({ error: err.message.includes('Duplicate') ? 'Email already registered.' : err.message });
            const student_id = r.insertId;

            db.query(
                'INSERT INTO USERS (name, email, password_hash, role, linked_id) VALUES (?,?,?,?,?)',
                [student_name, email, hash, 'student', student_id],
                (err2) => {
                    if (err2) return res.status(500).json({ error: err2.message });
                    res.json({ success: true, id: student_id, message: `Student "${student_name}" created.` });
                }
            );
        }
    );
});

// POST /api/auth/change-password
app.post('/api/auth/change-password', protect('super_admin','admin','student'), async (req, res) => {
    const { old_password, new_password } = req.body;
    db.query('SELECT * FROM USERS WHERE user_id = ?', [req.user.user_id], async (err, rows) => {
        if (err || !rows.length) return res.status(500).json({ error: 'User not found.' });
        const ok = await bcrypt.compare(old_password, rows[0].password_hash);
        if (!ok) return res.status(401).json({ error: 'Old password is incorrect.' });
        const hash = await bcrypt.hash(new_password, 10);
        db.query('UPDATE USERS SET password_hash=? WHERE user_id=?', [hash, req.user.user_id], (err2) => {
            if (err2) return res.status(500).json({ error: err2.message });
            res.json({ success: true });
        });
    });
});

// GET /api/auth/me
app.get('/api/auth/me', protect('super_admin','admin','student'), (req, res) => {
    res.json(req.user);
});

// ============================================================
// STATS
// ============================================================
app.get('/api/stats', protect('super_admin','admin'), (req, res) => {
    const adminId = getAdminId(req);
    const where   = adminId ? `WHERE admin_id = ${db.escape(adminId)}` : '';
    const sWhere  = adminId ? `WHERE s.admin_id = ${db.escape(adminId)}` : '';

    const sql = `SELECT
        (SELECT COUNT(*) FROM STUDENT ${where})                                       AS total_students,
        (SELECT COUNT(*) FROM ROOM    ${where})                                       AS total_rooms,
        (SELECT COUNT(*) FROM COMPLAINT c JOIN STUDENT s ON c.student_id=s.student_id
            ${sWhere ? sWhere.replace('WHERE', 'WHERE') : ''}
        )                                                                             AS pending_complaints,
        (SELECT IFNULL(SUM(p.amount),0) FROM PAYMENT p JOIN STUDENT s ON p.student_id=s.student_id
            ${sWhere ? sWhere.replace('WHERE s.', 'WHERE s.') : ''} ${sWhere ? 'AND' : 'WHERE'} p.payment_status='Paid'
        )                                                                             AS total_revenue`;

    db.query(sql, (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results[0]);
    });
});

// ============================================================
// ADMIN routes  (super_admin sees all, admin sees own)
// ============================================================
app.get('/api/admins', protect('super_admin'), (req, res) => {
    db.query('SELECT admin_id, admin_name, admin_email FROM ADMIN', (err, r) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(r);
    });
});
app.post('/api/admins', protect('super_admin'), async (req, res) => {
    const { admin_name, admin_email, password } = req.body;
    const hash = await bcrypt.hash(password || 'Admin@123', 10);
    db.query('INSERT INTO ADMIN (admin_name, admin_email) VALUES (?,?)', [admin_name, admin_email], (err, r) => {
        if (err) return res.status(500).json({ error: err.message });
        db.query('INSERT INTO USERS (name,email,password_hash,role,linked_id) VALUES (?,?,?,?,?)',
            [admin_name, admin_email, hash, 'admin', r.insertId], (e2) => {
            if (e2) return res.status(500).json({ error: e2.message });
            res.json({ success: true, id: r.insertId });
        });
    });
});
app.put('/api/admins/:id', protect('super_admin'), (req, res) => {
    const { admin_name, admin_email } = req.body;
    db.query('UPDATE ADMIN SET admin_name=?, admin_email=? WHERE admin_id=?', [admin_name, admin_email, req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});
app.delete('/api/admins/:id', protect('super_admin'), (req, res) => {
    db.query('DELETE FROM ADMIN WHERE admin_id=?', [req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

// ============================================================
// STUDENT routes
// ============================================================
app.get('/api/students', protect('super_admin','admin'), (req, res) => {
    const adminId = getAdminId(req);
    const sql     = adminId
        ? 'SELECT student_id,student_name,department,phone,email,guardian_name FROM STUDENT WHERE admin_id=?'
        : 'SELECT student_id,student_name,department,phone,email,guardian_name FROM STUDENT';
    db.query(sql, adminId ? [adminId] : [], (err, r) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(r);
    });
});
// Student gets their own profile
app.get('/api/students/me', protect('student'), (req, res) => {
    db.query('SELECT student_id,student_name,department,phone,email,guardian_name FROM STUDENT WHERE student_id=?',
        [req.user.linked_id], (err, r) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(r[0] || {});
    });
});
app.post('/api/students', protect('admin','super_admin'), async (req, res) => {
    const { student_name, department, phone, email, guardian_name, password } = req.body;
    const adminId = getAdminId(req) || req.body.admin_id;
    const hash    = await bcrypt.hash(password || 'Student@123', 10);
    db.query('INSERT INTO STUDENT (student_name,department,phone,email,guardian_name,admin_id) VALUES (?,?,?,?,?,?)',
        [student_name, department, phone, email, guardian_name, adminId], (err, r) => {
        if (err) return res.status(500).json({ error: err.message });
        db.query('INSERT INTO USERS (name,email,password_hash,role,linked_id) VALUES (?,?,?,?,?)',
            [student_name, email, hash, 'student', r.insertId], (e2) => {
            if (e2) return res.status(500).json({ error: e2.message });
            res.json({ success: true, id: r.insertId });
        });
    });
});
app.put('/api/students/:id', protect('admin','super_admin'), (req, res) => {
    const { student_name, department, phone, email, guardian_name } = req.body;
    db.query('UPDATE STUDENT SET student_name=?,department=?,phone=?,email=?,guardian_name=? WHERE student_id=?',
        [student_name, department, phone, email, guardian_name, req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});
app.delete('/api/students/:id', protect('admin','super_admin'), (req, res) => {
    db.query('DELETE FROM STUDENT WHERE student_id=?', [req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

// ============================================================
// ROOM routes
// ============================================================
app.get('/api/rooms', protect('super_admin','admin','student'), (req, res) => {
    const adminId = req.user.role === 'student' ? null : getAdminId(req);
    // students see all rooms (read-only), admins see own
    if (req.user.role === 'student') {
        // get admin_id of this student first
        db.query('SELECT admin_id FROM STUDENT WHERE student_id=?', [req.user.linked_id], (err, rows) => {
            if (err || !rows.length) return res.json([]);
            db.query('SELECT room_id,room_number,seat_capacity,room_status FROM ROOM WHERE admin_id=?',
                [rows[0].admin_id], (err2, r) => {
                if (err2) return res.status(500).json({ error: err2.message });
                res.json(r);
            });
        });
        return;
    }
    const sql = adminId
        ? 'SELECT room_id,room_number,seat_capacity,room_status FROM ROOM WHERE admin_id=?'
        : 'SELECT room_id,room_number,seat_capacity,room_status FROM ROOM';
    db.query(sql, adminId ? [adminId] : [], (err, r) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(r);
    });
});
app.post('/api/rooms', protect('admin','super_admin'), (req, res) => {
    const { room_number, seat_capacity, room_status } = req.body;
    const adminId = getAdminId(req) || req.body.admin_id;
    db.query('INSERT INTO ROOM (room_number,seat_capacity,room_status,admin_id) VALUES (?,?,?,?)',
        [room_number, seat_capacity, room_status, adminId], (err, r) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, id: r.insertId });
    });
});
app.put('/api/rooms/:id', protect('admin','super_admin'), (req, res) => {
    const { room_number, seat_capacity, room_status } = req.body;
    db.query('UPDATE ROOM SET room_number=?,seat_capacity=?,room_status=? WHERE room_id=?',
        [room_number, seat_capacity, room_status, req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});
app.delete('/api/rooms/:id', protect('admin','super_admin'), (req, res) => {
    db.query('DELETE FROM ROOM WHERE room_id=?', [req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

// ============================================================
// NOTICE routes
// ============================================================
app.get('/api/notices', protect('super_admin','admin','student'), (req, res) => {
    const adminId = req.user.role === 'student' ? null : getAdminId(req);

    if (req.user.role === 'student') {
        db.query('SELECT admin_id FROM STUDENT WHERE student_id=?', [req.user.linked_id], (err, rows) => {
            if (err || !rows.length) return res.json([]);
            db.query('SELECT notice_id,notice_title,DATE_FORMAT(publish_date,"%Y-%m-%d") AS publish_date FROM NOTICE WHERE admin_id=?',
                [rows[0].admin_id], (err2, r) => {
                if (err2) return res.status(500).json({ error: err2.message });
                res.json(r);
            });
        });
        return;
    }
    const sql = adminId
        ? 'SELECT notice_id,notice_title,DATE_FORMAT(publish_date,"%Y-%m-%d") AS publish_date FROM NOTICE WHERE admin_id=?'
        : 'SELECT notice_id,notice_title,DATE_FORMAT(publish_date,"%Y-%m-%d") AS publish_date FROM NOTICE';
    db.query(sql, adminId ? [adminId] : [], (err, r) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(r);
    });
});
app.post('/api/notices', protect('admin','super_admin'), (req, res) => {
    const { notice_title, publish_date } = req.body;
    const adminId = getAdminId(req) || req.body.admin_id;
    db.query('INSERT INTO NOTICE (notice_title,publish_date,admin_id) VALUES (?,?,?)',
        [notice_title, publish_date, adminId], (err, r) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, id: r.insertId });
    });
});
app.put('/api/notices/:id', protect('admin','super_admin'), (req, res) => {
    const { notice_title, publish_date } = req.body;
    db.query('UPDATE NOTICE SET notice_title=?,publish_date=? WHERE notice_id=?',
        [notice_title, publish_date, req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});
app.delete('/api/notices/:id', protect('admin','super_admin'), (req, res) => {
    db.query('DELETE FROM NOTICE WHERE notice_id=?', [req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

// ============================================================
// APPLICATION routes (Room Applications)
// ============================================================
app.get('/api/applications', protect('super_admin','admin','student'), (req, res) => {
    if (req.user.role === 'student') {
        db.query(`SELECT a.application_id, a.student_id, a.room_id, r.room_number, DATE_FORMAT(a.application_date,"%Y-%m-%d") AS application_date, a.application_status 
                  FROM APPLICATION a 
                  LEFT JOIN ROOM r ON a.room_id = r.room_id 
                  WHERE a.student_id=? ORDER BY a.application_id DESC`,
            [req.user.linked_id], (err, r) => { if (err) return res.status(500).json({ error: err.message }); res.json(r); });
        return;
    }
    const adminId = getAdminId(req);
    const sql = adminId
        ? `SELECT a.application_id, a.student_id, s.student_name, a.room_id, r.room_number, DATE_FORMAT(a.application_date,"%Y-%m-%d") AS application_date, a.application_status 
           FROM APPLICATION a 
           JOIN STUDENT s ON a.student_id=s.student_id 
           LEFT JOIN ROOM r ON a.room_id=r.room_id 
           WHERE s.admin_id=? ORDER BY a.application_id DESC`
        : `SELECT a.application_id, a.student_id, s.student_name, a.room_id, r.room_number, DATE_FORMAT(a.application_date,"%Y-%m-%d") AS application_date, a.application_status 
           FROM APPLICATION a 
           JOIN STUDENT s ON a.student_id=s.student_id 
           LEFT JOIN ROOM r ON a.room_id=r.room_id ORDER BY a.application_id DESC`;
    db.query(sql, adminId ? [adminId] : [], (err, r) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(r);
    });
});
app.post('/api/applications', protect('admin','super_admin','student'), (req, res) => {
    const { student_id, room_id, application_date, application_status } = req.body;
    const sid = req.user.role === 'student' ? req.user.linked_id : student_id;
    db.query('INSERT INTO APPLICATION (student_id, room_id, application_date, application_status) VALUES (?,?,?,?)',
        [sid, room_id || null, application_date || new Date().toISOString().split('T')[0], application_status || 'Pending'], (err, r) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, id: r.insertId });
    });
});
app.put('/api/applications/:id', protect('admin','super_admin'), (req, res) => {
    const { student_id, room_id, application_date, application_status } = req.body;
    db.query('UPDATE APPLICATION SET student_id=?, room_id=?, application_date=?, application_status=? WHERE application_id=?',
        [student_id, room_id || null, application_date, application_status, req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });

        // If approved, check if room capacity vs approved applications marks room Full
        if (application_status === 'Approved' && room_id) {
            db.query('SELECT seat_capacity FROM ROOM WHERE room_id=?', [room_id], (e1, rRows) => {
                if (!e1 && rRows.length) {
                    const cap = rRows[0].seat_capacity;
                    db.query('SELECT COUNT(*) as cnt FROM APPLICATION WHERE room_id=? AND application_status="Approved"', [room_id], (e2, cRows) => {
                        if (!e2 && cRows.length && cRows[0].cnt >= cap) {
                            db.query('UPDATE ROOM SET room_status="Full" WHERE room_id=?', [room_id]);
                        }
                    });
                }
            });
        }
        res.json({ success: true });
    });
});
app.delete('/api/applications/:id', protect('admin','super_admin'), (req, res) => {
    db.query('DELETE FROM APPLICATION WHERE application_id=?', [req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

// ============================================================
// PAYMENT routes
// ============================================================
app.get('/api/payments', protect('super_admin','admin','student'), (req, res) => {
    if (req.user.role === 'student') {
        db.query('SELECT payment_id,student_id,amount,payment_month,payment_status FROM PAYMENT WHERE student_id=?',
            [req.user.linked_id], (err, r) => { if (err) return res.status(500).json({ error: err.message }); res.json(r); });
        return;
    }
    const adminId = getAdminId(req);
    const sql = adminId
        ? 'SELECT p.payment_id,p.student_id,p.amount,p.payment_month,p.payment_status FROM PAYMENT p JOIN STUDENT s ON p.student_id=s.student_id WHERE s.admin_id=?'
        : 'SELECT payment_id,student_id,amount,payment_month,payment_status FROM PAYMENT';
    db.query(sql, adminId ? [adminId] : [], (err, r) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(r);
    });
});
app.post('/api/payments', protect('admin','super_admin'), (req, res) => {
    const { student_id, amount, payment_month, payment_status } = req.body;
    db.query('INSERT INTO PAYMENT (student_id,amount,payment_month,payment_status) VALUES (?,?,?,?)',
        [student_id, amount, payment_month, payment_status], (err, r) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, id: r.insertId });
    });
});
app.put('/api/payments/:id', protect('admin','super_admin'), (req, res) => {
    const { student_id, amount, payment_month, payment_status } = req.body;
    db.query('UPDATE PAYMENT SET student_id=?,amount=?,payment_month=?,payment_status=? WHERE payment_id=?',
        [student_id, amount, payment_month, payment_status, req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});
app.delete('/api/payments/:id', protect('admin','super_admin'), (req, res) => {
    db.query('DELETE FROM PAYMENT WHERE payment_id=?', [req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

// ============================================================
// COMPLAINT routes
// ============================================================
app.get('/api/complaints', protect('super_admin','admin','student'), (req, res) => {
    if (req.user.role === 'student') {
        db.query('SELECT complaint_id,student_id,complaint_text,complaint_status FROM COMPLAINT WHERE student_id=?',
            [req.user.linked_id], (err, r) => { if (err) return res.status(500).json({ error: err.message }); res.json(r); });
        return;
    }
    const adminId = getAdminId(req);
    const sql = adminId
        ? 'SELECT c.complaint_id,c.student_id,c.complaint_text,c.complaint_status FROM COMPLAINT c JOIN STUDENT s ON c.student_id=s.student_id WHERE s.admin_id=?'
        : 'SELECT complaint_id,student_id,complaint_text,complaint_status FROM COMPLAINT';
    db.query(sql, adminId ? [adminId] : [], (err, r) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(r);
    });
});
app.post('/api/complaints', protect('admin','super_admin','student'), (req, res) => {
    const { student_id, complaint_text, complaint_status } = req.body;
    const sid = req.user.role === 'student' ? req.user.linked_id : student_id;
    db.query('INSERT INTO COMPLAINT (student_id,complaint_text,complaint_status) VALUES (?,?,?)',
        [sid, complaint_text, complaint_status || 'Open'], (err, r) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, id: r.insertId });
    });
});
app.put('/api/complaints/:id', protect('admin','super_admin'), (req, res) => {
    const { student_id, complaint_text, complaint_status } = req.body;
    db.query('UPDATE COMPLAINT SET student_id=?,complaint_text=?,complaint_status=? WHERE complaint_id=?',
        [student_id, complaint_text, complaint_status, req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});
app.delete('/api/complaints/:id', protect('admin','super_admin'), (req, res) => {
    db.query('DELETE FROM COMPLAINT WHERE complaint_id=?', [req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

// ============================================================
// FOOD ORDER routes
// ============================================================
app.get('/api/food_orders', protect('super_admin','admin','student'), (req, res) => {
    if (req.user.role === 'student') {
        db.query('SELECT order_id,student_id,food_name,quantity,price,delivery_status FROM FOOD_ORDER WHERE student_id=?',
            [req.user.linked_id], (err, r) => { if (err) return res.status(500).json({ error: err.message }); res.json(r); });
        return;
    }
    const adminId = getAdminId(req);
    const sql = adminId
        ? 'SELECT f.order_id,f.student_id,f.food_name,f.quantity,f.price,f.delivery_status FROM FOOD_ORDER f JOIN STUDENT s ON f.student_id=s.student_id WHERE s.admin_id=?'
        : 'SELECT order_id,student_id,food_name,quantity,price,delivery_status FROM FOOD_ORDER';
    db.query(sql, adminId ? [adminId] : [], (err, r) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(r);
    });
});
app.post('/api/food_orders', protect('admin','super_admin','student'), (req, res) => {
    const { student_id, food_name, quantity, price, delivery_status } = req.body;
    const sid = req.user.role === 'student' ? req.user.linked_id : student_id;
    db.query('INSERT INTO FOOD_ORDER (student_id,food_name,quantity,price,delivery_status) VALUES (?,?,?,?,?)',
        [sid, food_name, quantity, price, delivery_status || 'Pending'], (err, r) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, id: r.insertId });
    });
});
app.put('/api/food_orders/:id', protect('admin','super_admin'), (req, res) => {
    const { student_id, food_name, quantity, price, delivery_status } = req.body;
    db.query('UPDATE FOOD_ORDER SET student_id=?,food_name=?,quantity=?,price=?,delivery_status=? WHERE order_id=?',
        [student_id, food_name, quantity, price, delivery_status, req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});
app.delete('/api/food_orders/:id', protect('admin','super_admin'), (req, res) => {
    db.query('DELETE FROM FOOD_ORDER WHERE order_id=?', [req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

// ============================================================
// TECH REPORT routes (admin reports to super_admin)
// ============================================================
app.get('/api/tech_reports', protect('super_admin','admin'), (req, res) => {
    if (req.user.role === 'admin') {
        // Admin sees only their own reports
        db.query('SELECT report_id, admin_id, report_subject, report_detail, report_status, DATE_FORMAT(created_at,"%Y-%m-%d %H:%i") AS created_at FROM TECH_REPORT WHERE admin_id=? ORDER BY created_at DESC',
            [req.user.linked_id], (err, r) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(r);
        });
        return;
    }
    // Super admin sees all reports with admin name
    db.query('SELECT t.report_id, t.admin_id, a.admin_name, t.report_subject, t.report_detail, t.report_status, DATE_FORMAT(t.created_at,"%Y-%m-%d %H:%i") AS created_at FROM TECH_REPORT t JOIN ADMIN a ON t.admin_id=a.admin_id ORDER BY t.created_at DESC',
        (err, r) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(r);
    });
});
app.post('/api/tech_reports', protect('admin'), (req, res) => {
    const { report_subject, report_detail } = req.body;
    if (!report_subject || !report_detail) return res.status(400).json({ error: 'Subject and detail are required.' });
    db.query('INSERT INTO TECH_REPORT (admin_id, report_subject, report_detail) VALUES (?,?,?)',
        [req.user.linked_id, report_subject, report_detail], (err, r) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, id: r.insertId });
    });
});
app.put('/api/tech_reports/:id', protect('super_admin'), (req, res) => {
    const { report_status } = req.body;
    db.query('UPDATE TECH_REPORT SET report_status=? WHERE report_id=?',
        [report_status, req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});
app.delete('/api/tech_reports/:id', protect('super_admin'), (req, res) => {
    db.query('DELETE FROM TECH_REPORT WHERE report_id=?', [req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

// ============================================================
// GET /api/admins/list  — public list of admins for signup dropdown
// ============================================================
app.get('/api/admins/list', (req, res) => {
    db.query('SELECT admin_id, admin_name FROM ADMIN', (err, r) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(r);
    });
});

// ============================================================
// SETUP ROUTE — Run once to seed super_admin + demo accounts
// Visit: http://localhost:3000/api/setup  (GET)
// ============================================================
app.get('/api/setup', async (req, res) => {
    try {
        const saHash = await bcrypt.hash('SuperAdmin@123', 10);
        const aHash  = await bcrypt.hash('Admin@123',      10);
        const sHash  = await bcrypt.hash('Student@123',    10);

        // Super Admin
        db.query(`INSERT IGNORE INTO USERS (name,email,password_hash,role,linked_id)
                  VALUES ('Super Admin','superadmin@hms.com',?,?,NULL)`, [saHash,'super_admin'], () => {});

        // Admin 1  (linked to admin_id=1 from seed data)
        db.query(`INSERT IGNORE INTO USERS (name,email,password_hash,role,linked_id)
                  VALUES ('Ashikul Admin','admin@hostel.edu',?,?,1)`, [aHash,'admin'], () => {});

        // Students 1-5
        const students = [
            [1,'rakib@student.edu'],
            [2,'priya@student.edu'],
            [3,'nusrat@student.edu'],
            [4,'tanvir@student.edu'],
            [5,'sadia@student.edu'],
        ];
        for (const [sid, email] of students) {
            db.query(`INSERT IGNORE INTO USERS (name,email,password_hash,role,linked_id)
                      VALUES ((SELECT student_name FROM STUDENT WHERE student_id=?),?,?,?,?)`,
                [sid, email, sHash, 'student', sid], () => {});
        }

        res.send(`
            <h2>✅ Setup Complete!</h2>
            <p><strong>Super Admin:</strong> superadmin@hms.com / SuperAdmin@123</p>
            <p><strong>Admin:</strong> admin@hostel.edu / Admin@123</p>
            <p><strong>Students:</strong> rakib@student.edu / Student@123 (and priya, nusrat, tanvir, sadia)</p>
            <br><a href="/api/setup" style="display:none"></a>
            <p>Now open <a href="../login.html">login.html</a></p>
        `);
    } catch (e) {
        res.status(500).send('Setup failed: ' + e.message);
    }
});

// ============================================================
// START
// ============================================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Backend running on http://localhost:${PORT}`));