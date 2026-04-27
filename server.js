const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

dotenv.config();

const app = express();
const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

app.use(cors());
app.use(express.json());

// ============================================
// HELPER FUNCTIONS
// ============================================

const generateToken = (userId, role) => {
  return jwt.sign(
    { userId, role },
    process.env.JWT_SECRET || 'your-secret-key-change-in-production',
    { expiresIn: '8h' }
  );
};

const verifyToken = (token) => {
  try {
    return jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key-change-in-production');
  } catch (error) {
    return null;
  }
};

// ============================================
// STUDENT LOGIN
// ============================================

app.post('/api/auth/student-login', async (req, res) => {
  try {
    const { reg_no, password } = req.body;

    if (!reg_no || !password) {
      return res.status(400).json({ error: 'Registration number and password required' });
    }

    // For now, accept any password (we'll add proper password hashing later)
    // In production, you'd hash passwords and compare
    const query = `
      SELECT s.id, s.reg_no, s.full_name, s.email, p.code as programme, 
             s.year_of_study, s.semester, s.status
      FROM students s
      LEFT JOIN programmes p ON s.programme_id = p.id
      WHERE s.reg_no = $1
    `;

    const result = await pool.query(query, [reg_no]);

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid registration number or password' });
    }

    const student = result.rows[0];
    const token = generateToken(student.id, 'student');

    res.json({
      success: true,
      token,
      student: {
        id: student.id,
        reg_no: student.reg_no,
        full_name: student.full_name,
        email: student.email,
        programme: student.programme,
        year_of_study: student.year_of_study,
        semester: student.semester,
        status: student.status
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============================================
// LECTURER LOGIN
// ============================================

app.post('/api/auth/lecturer-login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    const query = `
      SELECT id, staff_no, full_name, email, role, teaching_days
      FROM staff
      WHERE email = $1 AND role IN ('lecturer', 'admin', 'super_admin')
    `;

    const result = await pool.query(query, [email]);

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const staff = result.rows[0];
    const token = generateToken(staff.id, staff.role);

    res.json({
      success: true,
      token,
      staff: {
        id: staff.id,
        staff_no: staff.staff_no,
        full_name: staff.full_name,
        email: staff.email,
        role: staff.role,
        teaching_days: staff.teaching_days
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============================================
// GET STUDENT PROFILE
// ============================================

app.get('/api/student/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }

    const decoded = verifyToken(token);
    if (!decoded || decoded.role !== 'student') {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    const query = `
      SELECT s.id, s.reg_no, s.full_name, s.email, s.phone, s.gender,
             p.code as programme, p.name as programme_name,
             s.year_of_study, s.semester, s.enrollment_year, s.status
      FROM students s
      LEFT JOIN programmes p ON s.programme_id = p.id
      WHERE s.id = $1
    `;

    const result = await pool.query(query, [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Student not found' });
    }

    res.json({ success: true, student: result.rows[0] });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============================================
// GET STUDENT COURSES (REGISTERED)
// ============================================

app.get('/api/student/:id/courses', async (req, res) => {
  try {
    const { id } = req.params;
    const token = req.headers.authorization?.split(' ')[1];

    if (!token || !verifyToken(token)) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const query = `
      SELECT c.id, c.code, c.title, c.credit_units, c.lecture_hours, 
             c.practical_hours, c.contact_hours, s.full_name as lecturer_name
      FROM registrations r
      JOIN courses c ON r.course_id = c.id
      LEFT JOIN staff s ON c.assigned_staff_id = s.id
      WHERE r.student_id = $1 AND r.status = 'active'
      ORDER BY c.code
    `;

    const result = await pool.query(query, [id]);
    res.json({ success: true, courses: result.rows });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============================================
// GET STUDENT RESULTS
// ============================================

app.get('/api/student/:id/results', async (req, res) => {
  try {
    const { id } = req.params;
    const token = req.headers.authorization?.split(' ')[1];

    if (!token || !verifyToken(token)) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const query = `
      SELECT r.id, c.code, c.title, r.marks, r.letter_grade, r.gpa_points,
             sem.academic_year, sem.semester_no, r.remarks, r.is_published
      FROM results r
      JOIN courses c ON r.course_id = c.id
      JOIN semesters sem ON r.semester_id = sem.id
      WHERE r.student_id = $1
      ORDER BY sem.academic_year DESC, sem.semester_no DESC, c.code
    `;

    const result = await pool.query(query, [id]);
    res.json({ success: true, results: result.rows });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============================================
// HEALTH CHECK
// ============================================

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', message: 'FAES MIS Backend is running' });
});

// ============================================
// START SERVER
// ============================================

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`🚀 FAES MIS Backend running on port ${PORT}`);
});
