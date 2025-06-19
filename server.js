// ===============================================
//  1. استيراد المكتبات المطلوبة
// ===============================================
const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// ===============================================
//  2. إعداد التطبيق والميدلوير (Middlewares)
// ===============================================
const app = express();
app.use(cors());
app.use(express.json());

// ===============================================
//  3. إعداد الاتصال بقاعدة البيانات
// ===============================================
const db = mysql.createConnection({
    host: 'localhost',
    user: 'elibrary_user',
    password: 'password123',
    database: 'e_library_db'
});

// **مهم جداً: محاولة الاتصال بقاعدة البيانات مباشرة بعد الإعداد**
db.connect(err => {
    if (err) {
        console.error('Error connecting to database:', err);
        return;
    }
    console.log('Successfully connected to MySQL database.');
});


// ===============================================
//  4. تعريف الحراس (Middleware) والمسارات (API Routes)
// ===============================================

// --- Middleware to verify Admin role ---
const verifyAdmin = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) {
        return res.status(403).json({ message: 'A token is required for authentication.' });
    }
    try {
        const decoded = jwt.verify(token, 'YOUR_SECRET_KEY');
        const sql = 'SELECT role FROM User WHERE lid = ?';
        db.query(sql, [decoded.userId], (err, results) => {
            if (err || results.length === 0) {
                return res.status(500).json({ message: 'Failed to authenticate user.' });
            }
            const userRole = results[0].role;
            if (userRole !== 'admin') {
                return res.status(403).json({ message: 'Access denied. Admin role required.' });
            }
            req.user = decoded;
            next();
        });
    } catch (err) {
        return res.status(401).json({ message: 'Invalid Token.' });
    }
};

// --- Route التجريبي ---
app.get('/', (req, res) => {
    res.send('<h1>Welcome to E_Library Backend API</h1>');
});

// --- Route لتسجيل مستخدم جديد ---
app.post('/api/signup', async (req, res) => {
    try {
        const { Username, password, FName, LName } = req.body;
        if (!Username || !password) {
            return res.status(400).json({ message: 'Username and password are required.' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = { Username, password: hashedPassword, FName, LName };
        const sql = 'INSERT INTO User SET ?';
        db.query(sql, newUser, (err, result) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') {
                    return res.status(409).json({ message: 'Username already exists.' });
                }
                console.error('Error inserting user:', err);
                return res.status(500).json({ message: 'Database error.' });
            }
            res.status(201).json({ message: 'User created successfully!', userId: result.insertId });
        });
    } catch (error) {
        console.error('Server error during signup:', error);
        res.status(500).json({ message: 'Internal server error.' });
    }
});

// --- Route لتسجيل الدخول ---
app.post('/api/login', (req, res) => {
    const { Username, password } = req.body;
    const sql = 'SELECT * FROM User WHERE Username = ?';
    db.query(sql, [Username], async (err, results) => {
        if (err) {
            console.error('Database error during login:', err);
            return res.status(500).json({ message: 'Database error.' });
        }
        if (results.length === 0) {
            return res.status(401).json({ message: 'Invalid username or password.' });
        }
        const user = results[0];
        const isPasswordMatch = await bcrypt.compare(password, user.password);
        if (!isPasswordMatch) {
            return res.status(401).json({ message: 'Invalid username or password.' });
        }
        const token = jwt.sign(
            { userId: user.lid, username: user.Username },
            'YOUR_SECRET_KEY',
            { expiresIn: '1h' }
        );
        res.status(200).json({ message: 'Login successful!', token: token });
    });
});


// --- Route لإضافة مؤلف جديد (للمدير فقط) ---
app.post('/api/authors', verifyAdmin, (req, res) => {
    try {
        const { Fname, Lname, Country, City, Address } = req.body;
        if (!Fname || !Lname) {
            return res.status(400).json({ message: 'First name and last name are required.' });
        }
        const newAuthor = { Fname, Lname, Country, City, Address };
        const sql = 'INSERT INTO Author SET ?';
        db.query(sql, newAuthor, (err, result) => {
            if (err) {
                console.error('Error inserting author:', err);
                return res.status(500).json({ message: 'Database error while adding author.' });
            }
            res.status(201).json({ message: 'Author added successfully!', authorId: result.insertId });
        });
    } catch (error) {
        console.error('Server error while adding author:', error);
        res.status(500).json({ message: 'Internal server error.' });
    }
});

// --- API Route to Add a Publisher (Admin Only) ---
app.post('/api/publishers', verifyAdmin, (req, res) => {
    try {
        // 1. الحصول على بيانات الناشر من الطلب
        const { PName, City } = req.body;

        // 2. التحقق من وجود اسم الناشر
        if (!PName) {
            return res.status(400).json({ message: 'Publisher name is required.' });
        }

        const newPublisher = { PName, City };

        // 3. كتابة استعلام SQL لإضافة الناشر
        const sql = 'INSERT INTO Publisher SET ?';

        // 4. تنفيذ الاستعلام
        db.query(sql, newPublisher, (err, result) => {
            if (err) {
                console.error('Error inserting publisher:', err);
                return res.status(500).json({ message: 'Database error while adding publisher.' });
            }
            res.status(201).json({ message: 'Publisher added successfully!', publisherId: result.insertId });
        });
    } catch (error) {
        console.error('Server error while adding publisher:', error);
        res.status(500).json({ message: 'Internal server error.' });
    }
});

// --- API Route to Add a Book (Admin Only) ---
app.post('/api/books', verifyAdmin, (req, res) => {
    try {
        // 1. الحصول على بيانات الكتاب من الطلب
        const { Title, Type, Price, publd, Authorld } = req.body;

        // 2. التحقق من وجود البيانات الأساسية
        if (!Title || !publd || !Authorld) {
            return res.status(400).json({ message: 'Title, publisher ID, and author ID are required.' });
        }

        const newBook = { Title, Type, Price, publd, Authorld };

        // 3. كتابة استعلام SQL لإضافة الكتاب
        const sql = 'INSERT INTO Book SET ?';

        // 4. تنفيذ الاستعلام
        db.query(sql, newBook, (err, result) => {
            if (err) {
                // هذا الخطأ قد يحدث إذا كان رقم المؤلف أو الناشر غير موجود
                console.error('Error inserting book:', err);
                return res.status(500).json({ message: 'Database error while adding book. Check if author and publisher IDs are correct.' });
            }
            res.status(201).json({ message: 'Book added successfully!', bookId: result.insertId });
        });
    } catch (error) {
        console.error('Server error while adding book:', error);
        res.status(500).json({ message: 'Internal server error.' });
    }
});


// --- API Route to Get All Books (Public) ---
app.get('/api/books', (req, res) => {
    // هذا الاستعلام سيقوم بدمج معلومات من ثلاث جداول مختلفة
    // 1. كل الأعمدة من جدول Book
    // 2. اسم المؤلف الكامل (Fname + Lname) من جدول Author
    // 3. اسم الناشر (PName) من جدول Publisher
    const sql = `
        SELECT 
            Book.*, 
            CONCAT(Author.Fname, ' ', Author.Lname) AS AuthorName,
            Publisher.PName AS PublisherName
        FROM Book
        JOIN Author ON Book.Authorld = Author.Id
        JOIN Publisher ON Book.publd = Publisher.Id
    `;

    db.query(sql, (err, results) => {
        if (err) {
            console.error('Error fetching books:', err);
            return res.status(500).json({ message: 'Database error while fetching books.' });
        }
        // في حال النجاح، أرسل قائمة الكتب
        res.status(200).json(results);
    });
});


// --- API Route to Search for a Book by Title (Public) ---
app.get('/api/search/books', (req, res) => {
    // 1. الحصول على جزء العنوان من الطلب (query parameter)
    const partialTitle = req.query.title;

    if (!partialTitle) {
        return res.status(400).json({ message: 'A "title" query parameter is required for searching.' });
    }

    // 2. نفس استعلام الدمج السابق، ولكن مع إضافة شرط WHERE للبحث
    // نستخدم LIKE و % للبحث عن أي كتاب يحتوي على النص المرسل
    const sql = `
        SELECT 
            Book.*, 
            CONCAT(Author.Fname, ' ', Author.Lname) AS AuthorName,
            Publisher.PName AS PublisherName
        FROM Book
        JOIN Author ON Book.Authorld = Author.Id
        JOIN Publisher ON Book.publd = Publisher.Id
        WHERE Book.Title LIKE ?
    `;

    // نضع النص بين علامتي % ليتم البحث في أي مكان في العنوان
    const searchTerm = `%${partialTitle}%`;

    db.query(sql, [searchTerm], (err, results) => {
        if (err) {
            console.error('Error searching for books:', err);
            return res.status(500).json({ message: 'Database error while searching for books.' });
        }
        // أرسل قائمة الكتب التي تطابقت مع البحث
        res.status(200).json(results);
    });
});

// --- API Route to Search for an Author by Name (Public) ---
app.get('/api/search/authors', (req, res) => {
    // 1. الحصول على جزء الاسم من الطلب
    const partialName = req.query.name;

    if (!partialName) {
        return res.status(400).json({ message: 'A "name" query parameter is required for searching.' });
    }

    // 2. كتابة استعلام للبحث في حقل الاسم الأول أو الاسم الأخير
    const sql = `
        SELECT * FROM Author 
        WHERE Fname LIKE ? OR Lname LIKE ?
    `;

    const searchTerm = `%${partialName}%`;

    // نمرر نفس مصطلح البحث مرتين، مرة للاسم الأول ومرة للأخير
    db.query(sql, [searchTerm, searchTerm], (err, results) => {
        if (err) {
            console.error('Error searching for authors:', err);
            return res.status(500).json({ message: 'Database error while searching for authors.' });
        }
        res.status(200).json(results);
    });
});

// --- API Route to Search for a Publisher by Name (Public) ---
app.get('/api/search/publishers', (req, res) => {
    const partialName = req.query.name;

    if (!partialName) {
        return res.status(400).json({ message: 'A "name" query parameter is required for searching.' });
    }

    const sql = `SELECT * FROM Publisher WHERE PName LIKE ?`;
    const searchTerm = `%${partialName}%`;

    db.query(sql, [searchTerm], (err, results) => {
        if (err) {
            console.error('Error searching for publishers:', err);
            return res.status(500).json({ message: 'Database error while searching for publishers.' });
        }
        res.status(200).json(results);
    });
});




// --- API Route to Get a Single Book's Details (Public) ---
app.get('/api/books/:id', (req, res) => {
    // 1. الحصول على رقم الكتاب من الرابط (route parameter)
    const bookId = req.params.id;

    // 2. نفس استعلام الدمج السابق، مع إضافة شرط WHERE للبحث برقم الكتاب
    const sql = `
        SELECT 
            Book.*, 
            CONCAT(Author.Fname, ' ', Author.Lname) AS AuthorName,
            Author.Country AS AuthorCountry,
            Author.City AS AuthorCity,
            Publisher.PName AS PublisherName,
            Publisher.City AS PublisherCity
        FROM Book
        JOIN Author ON Book.Authorld = Author.Id
        JOIN Publisher ON Book.publd = Publisher.Id
        WHERE Book.Id = ?
    `;

    db.query(sql, [bookId], (err, results) => {
        if (err) {
            console.error('Error fetching book details:', err);
            return res.status(500).json({ message: 'Database error.' });
        }
        // التحقق إذا كان الكتاب غير موجود
        if (results.length === 0) {
            return res.status(404).json({ message: 'Book not found.' });
        }
        // أرسل بيانات الكتاب الوحيد الذي تم العثور عليه
        res.status(200).json(results[0]);
    });
});


// --- API Route to Get All Books by a Specific Author (Public) ---
app.get('/api/authors/:id/books', (req, res) => {
    const authorId = req.params.id;
    const sql = `SELECT * FROM Book WHERE Authorld = ?`;

    db.query(sql, [authorId], (err, results) => {
        if (err) {
            console.error('Error fetching books by author:', err);
            return res.status(500).json({ message: 'Database error.' });
        }
        res.status(200).json(results);
    });
});

// --- API Route to Get All Books by a Specific Publisher (Public) ---
app.get('/api/publishers/:id/books', (req, res) => {
    const publisherId = req.params.id;
    const sql = `SELECT * FROM Book WHERE publd = ?`;

    db.query(sql, [publisherId], (err, results) => {
        if (err) {
            console.error('Error fetching books by publisher:', err);
            return res.status(500).json({ message: 'Database error.' });
        }
        res.status(200).json(results);
    });
});


// ===============================================
//  5. تشغيل الخادم
// ===============================================
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
