-- ============================================================
--  HOSTEL MANAGEMENT SYSTEM — Complete Database Schema v2
--  Includes: 3-Tier Auth (super_admin / admin / student)
--  Run this ENTIRE file in phpMyAdmin SQL tab
-- ============================================================

DROP DATABASE IF EXISTS hostel_management;
CREATE DATABASE hostel_management CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE hostel_management;

-- ============================================================
-- TABLE 1: ADMIN
-- ============================================================
CREATE TABLE ADMIN (
    admin_id    INT          NOT NULL AUTO_INCREMENT,
    admin_name  VARCHAR(100) NOT NULL,
    admin_email VARCHAR(150) NOT NULL UNIQUE,
    PRIMARY KEY (admin_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================
-- TABLE 2: STUDENT
-- ============================================================
CREATE TABLE STUDENT (
    student_id    INT          NOT NULL AUTO_INCREMENT,
    student_name  VARCHAR(100) NOT NULL,
    department    VARCHAR(100) NOT NULL,
    phone         VARCHAR(20)  NOT NULL,
    email         VARCHAR(150) NOT NULL UNIQUE,
    guardian_name VARCHAR(100) NOT NULL,
    admin_id      INT          NOT NULL,   -- which admin owns this student
    PRIMARY KEY (student_id),
    FOREIGN KEY (admin_id) REFERENCES ADMIN(admin_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================
-- TABLE 3: ROOM
-- ============================================================
CREATE TABLE ROOM (
    room_id       INT         NOT NULL AUTO_INCREMENT,
    room_number   VARCHAR(20) NOT NULL,
    seat_capacity INT         NOT NULL DEFAULT 2,
    room_status   ENUM('Available','Full','Under Maintenance') NOT NULL DEFAULT 'Available',
    admin_id      INT         NOT NULL,   -- which admin owns this room
    PRIMARY KEY (room_id),
    UNIQUE KEY uq_room_per_admin (room_number, admin_id),
    FOREIGN KEY (admin_id) REFERENCES ADMIN(admin_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================
-- TABLE 4: NOTICE
-- ============================================================
CREATE TABLE NOTICE (
    notice_id    INT          NOT NULL AUTO_INCREMENT,
    notice_title VARCHAR(255) NOT NULL,
    publish_date DATE         NOT NULL DEFAULT (CURRENT_DATE),
    admin_id     INT          NOT NULL,   -- which admin posted this notice
    PRIMARY KEY (notice_id),
    FOREIGN KEY (admin_id) REFERENCES ADMIN(admin_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================
-- TABLE 5: APPLICATION
-- ============================================================
CREATE TABLE APPLICATION (
    application_id     INT  NOT NULL AUTO_INCREMENT,
    student_id         INT  NOT NULL,
    room_id            INT  NULL,
    application_date   DATE NOT NULL DEFAULT (CURRENT_DATE),
    application_status ENUM('Pending','Approved','Rejected') NOT NULL DEFAULT 'Pending',
    PRIMARY KEY (application_id),
    FOREIGN KEY (student_id) REFERENCES STUDENT(student_id) ON DELETE CASCADE,
    FOREIGN KEY (room_id) REFERENCES ROOM(room_id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================
-- TABLE 6: PAYMENT
-- ============================================================
CREATE TABLE PAYMENT (
    payment_id      INT            NOT NULL AUTO_INCREMENT,
    student_id      INT            NOT NULL,
    amount          DECIMAL(10,2)  NOT NULL,
    payment_month   VARCHAR(50)    NOT NULL,
    payment_method  VARCHAR(50)    NOT NULL DEFAULT 'bKash/Nagad',
    transaction_id  VARCHAR(100)   NULL,
    payment_status  ENUM('Paid','Unpaid','Processing') NOT NULL DEFAULT 'Unpaid',
    created_at      DATETIME       DEFAULT NOW(),
    PRIMARY KEY (payment_id),
    FOREIGN KEY (student_id) REFERENCES STUDENT(student_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================
-- TABLE 7: COMPLAINT
-- ============================================================
CREATE TABLE COMPLAINT (
    complaint_id     INT  NOT NULL AUTO_INCREMENT,
    student_id       INT  NOT NULL,
    complaint_text   TEXT NOT NULL,
    complaint_status ENUM('Open','Processing','Resolved') NOT NULL DEFAULT 'Open',
    PRIMARY KEY (complaint_id),
    FOREIGN KEY (student_id) REFERENCES STUDENT(student_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================
-- TABLE 8: FOOD_ORDER
-- ============================================================
CREATE TABLE FOOD_ORDER (
    order_id        INT            NOT NULL AUTO_INCREMENT,
    student_id      INT            NOT NULL,
    food_name       VARCHAR(150)   NOT NULL,
    quantity        INT            NOT NULL DEFAULT 1,
    price           DECIMAL(10,2)  NOT NULL,
    delivery_status ENUM('Pending','Processing','Delivered') NOT NULL DEFAULT 'Pending',
    PRIMARY KEY (order_id),
    FOREIGN KEY (student_id) REFERENCES STUDENT(student_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================
-- TABLE 9: USERS  (Auth table — all 3 roles)
-- ============================================================
CREATE TABLE USERS (
    user_id       INT          NOT NULL AUTO_INCREMENT,
    name          VARCHAR(100) NOT NULL,
    email         VARCHAR(150) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role          ENUM('super_admin','admin','student') NOT NULL DEFAULT 'student',
    linked_id     INT          NULL,   -- admin_id OR student_id
    is_active     TINYINT(1)   NOT NULL DEFAULT 1,
    created_at    DATETIME     DEFAULT NOW(),
    PRIMARY KEY (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================
-- SEED DATA
-- ============================================================

-- Admins
INSERT INTO ADMIN (admin_name, admin_email) VALUES
('Ashikul Admin',  'admin@hostel.edu'),
('Demo School',    'demo@school.edu');

-- Students (linked to admin_id=1)
INSERT INTO STUDENT (student_name, department, phone, email, guardian_name, admin_id) VALUES
('Rakib Hassan',  'Computer Science',  '01711-111111', 'rakib@student.edu',  'Karim Hassan', 1),
('Priya Das',     'Electrical Eng.',   '01722-222222', 'priya@student.edu',  'Subrata Das',  1),
('Nusrat Jahan',  'Business Admin',    '01733-333333', 'nusrat@student.edu', 'Jalal Uddin',  1),
('Tanvir Ahmed',  'Civil Engineering', '01744-444444', 'tanvir@student.edu', 'Rafiq Ahmed',  1),
('Sadia Islam',   'Mathematics',       '01755-555555', 'sadia@student.edu',  'Anwar Islam',  1);

-- Rooms (linked to admin_id=1)
INSERT INTO ROOM (room_number, seat_capacity, room_status, admin_id) VALUES
('R-101', 4, 'Available',        1),
('R-102', 2, 'Full',             1),
('R-103', 3, 'Available',        1),
('R-201', 4, 'Under Maintenance',1),
('R-202', 2, 'Available',        1);

-- Notices (linked to admin_id=1)
INSERT INTO NOTICE (notice_title, publish_date, admin_id) VALUES
('Hostel Fee Deadline - July 2025',  '2025-06-25', 1),
('Electricity Maintenance Notice',   '2025-06-28', 1),
('New Meal Plan Announcement',       '2025-07-01', 1),
('Fire Drill Scheduled for July 10', '2025-07-03', 1);

-- Applications
INSERT INTO APPLICATION (student_id, room_id, application_date, application_status) VALUES
(1, 1, '2025-06-01','Approved'), (2, 1, '2025-06-05','Approved'),
(3, 3, '2025-06-10','Pending'),  (4, 5, '2025-06-12','Rejected'),
(5, 5, '2025-06-15','Pending');

-- Payments
INSERT INTO PAYMENT (student_id, amount, payment_month, payment_method, transaction_id, payment_status) VALUES
(1, 3500.00, 'July 2026', 'bKash', 'TRX987123', 'Paid'),
(1, 3500.00, 'August 2026', 'bKash', 'TRX987124', 'Processing'),
(2, 3500.00, 'July 2026', 'Nagad', 'TRX654321', 'Paid'),
(3, 3500.00, 'July 2026', 'N/A', NULL, 'Unpaid');

-- Complaints
INSERT INTO COMPLAINT (student_id, complaint_text, complaint_status) VALUES
(1,'Water leaking from bathroom ceiling.',     'Processing'),
(2,'WiFi speed is very slow at night.',        'Open'),
(3,'Room heater not working since last week.', 'Open'),
(4,'Noisy neighbours disturbing study.',       'Resolved'),
(5,'Dining hall food quality has decreased.',  'Open');

-- Food Orders
INSERT INTO FOOD_ORDER (student_id, food_name, quantity, price, delivery_status) VALUES
(1,'Chicken Biryani',  2,180.00,'Delivered'),
(2,'Beef Burger',      1, 90.00,'Processing'),
(3,'Vegetable Soup',   3, 60.00,'Pending'),
(4,'Egg Fried Rice',   2,120.00,'Delivered'),
(5,'Chicken Sandwich', 1, 75.00,'Pending'),
(1,'Mango Juice',      2, 50.00,'Processing');

-- ============================================================
-- TABLE 10: TECH_REPORT
-- ============================================================
CREATE TABLE TECH_REPORT (
    report_id      INT          NOT NULL AUTO_INCREMENT,
    admin_id       INT          NOT NULL,
    report_subject VARCHAR(255) NOT NULL,
    report_detail  TEXT         NOT NULL,
    report_status  ENUM('Open','In Progress','Resolved') NOT NULL DEFAULT 'Open',
    created_at     DATETIME     DEFAULT NOW(),
    PRIMARY KEY (report_id),
    FOREIGN KEY (admin_id) REFERENCES ADMIN(admin_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Tech Reports
INSERT INTO TECH_REPORT (admin_id, report_subject, report_detail, report_status) VALUES
(1, 'Database backup failing', 'Automated daily backup script has been failing since July 25th.', 'Open'),
(1, 'Student portal login slow', 'Students are reporting slow login times during peak hours.', 'In Progress');

-- ============================================================
-- USERS seed  — passwords are set by the setup script (server.js)
-- Run: node server.js --setup   to hash and insert these accounts
-- ============================================================
-- super_admin@hms.com  / SuperAdmin@123
-- admin@hostel.edu     / Admin@123
-- rakib@student.edu    / Student@123
-- (etc — see server.js --setup output)
