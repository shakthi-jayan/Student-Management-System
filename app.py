from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, jsonify    
import mysql.connector
from mysql.connector import Error
from datetime import datetime, date, timedelta    
import pandas as pd
import csv
import io
from io import BytesIO
from flask import Response
import bcrypt
import uuid
import os
from werkzeug.utils import secure_filename
import razorpay
import logging
import re
import jwt

# Set up logging for debugging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# MySQL Root Configuration
MYSQL_ROOT_USER = 'root'
MYSQL_ROOT_PASSWORD = ''

# Admin database name
ADMIN_DB = 'admin_db'

RAZORPAY_KEY_ID = 'rzp_test_QXqCaFTaw7eitk'
RAZORPAY_KEY_SECRET = 'Af4cqMgxwUkJB1eSyddhRhf8'
razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))

def connect_db(user, password, db):
    try:
        connection = mysql.connector.connect(
            host="127.0.0.1",
            user=user,
            password=password,
            database=db,
            charset='utf8'
        )
        return connection
    except Error as e:
        print(f"Error: {e}")
        return None
        
def get_logo_path(db, user):
    DATABASES = get_databases()
    if db not in DATABASES:
        return 'image/logo.png'
    connection = connect_db(user, DATABASES[db]['password'], db)
    if connection:
        cursor = connection.cursor(dictionary=True)
        try:
            cursor.execute("SELECT logo_path FROM user_settings WHERE user = %s", (user,))
            result = cursor.fetchone()
            return result['logo_path'] if result and result['logo_path'] else 'image/logo.png'
        except Error as e:
            print(f"Error fetching logo path: {e}")
            return 'image/logo.png'
        finally:
            cursor.close()
            connection.close()
    return 'image/logo.png'

def get_databases():
    admin_conn = get_admin_connection()
    if admin_conn:
        cursor = admin_conn.cursor(dictionary=True)
        try:
            cursor.execute("SELECT db_name, db_user, db_password, updated_at FROM database_configs")
            return {
                row['db_name']: {
                    'user': row['db_user'], 
                    'password': row['db_password'],
                    'trial_expires': row['updated_at']
                } 
                for row in cursor.fetchall()
            }
        finally:
            cursor.close()
            admin_conn.close()
    return {}

@app.route('/')
def index():
    return redirect(url_for('register'))

@app.route('/create_order', methods=['POST'])
def create_order():
    data = request.json
    amount = data.get('amount')
    currency = data.get('currency', 'INR')
        
    try:
        order = razorpay_client.order.create({
            'amount': amount,
            'currency': currency,
            'payment_capture': 1
        })
            
        return jsonify({
            'success': True,
            'order': order
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 400
        
# Directory for logo uploads
UPLOAD_FOLDER = 'static/image'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['TRIAL_PERIOD_DAYS'] = 7
app.config['SECRET_KEY'] = 'your_secret_key_for_jwt'

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_root_connection():
    try:
        return mysql.connector.connect(
            host="127.0.0.1",  # Update if different
            port=3306,        # Update if different
            user=MYSQL_ROOT_USER,
            password=MYSQL_ROOT_PASSWORD,
            charset='utf8'
        )
    except Error as e:
        logger.error(f"Root connection error: {e}")
        return None

def get_admin_connection():
    try:
        conn = mysql.connector.connect(
                host="127.0.0.1",  # Update if different
                port=3306,        # Update if different
                user=MYSQL_ROOT_USER,
                password=MYSQL_ROOT_PASSWORD,
                database=ADMIN_DB,
                charset='utf8'
            )
        logger.info(f"Successfully connected to {ADMIN_DB}")
        return conn
    except Error as e:
        logger.error(f"Admin connection error: {e}")
        return None

from datetime import datetime, date, timedelta

def strftime(value, format='%B %Y'):
    if not value:
        return ''
    try:
        if isinstance(value, datetime):
            return value.strftime(format)
        return datetime.strptime(value, '%Y-%m').strftime(format)
    except (ValueError, TypeError):
        return value
app.jinja_env.filters['strftime'] = strftime

def floatformat(value, decimals=2):
    return f"{value:.{decimals}f}"
app.jinja_env.filters['floatformat'] = floatformat

def is_digit(value):
    return str(value).isdigit()
app.jinja_env.filters['is_digit'] = is_digit

def initialize_admin_database():
    root_conn = get_root_connection()
    if not root_conn:
        print("Failed to connect as root user")
        return
        
    cursor = root_conn.cursor()
    try:
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {ADMIN_DB}")
        root_conn.commit()
            
        admin_conn = get_admin_connection()
        admin_cursor = admin_conn.cursor(dictionary=True)
            
        admin_cursor.execute("""
            CREATE TABLE IF NOT EXISTS admin_users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
            
        admin_cursor.execute("""
            CREATE TABLE IF NOT EXISTS database_configs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                db_name VARCHAR(50) UNIQUE NOT NULL,
                db_user VARCHAR(50) NOT NULL,
                db_password VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME
            )
        """)
            
        admin_cursor.execute("SELECT COUNT(*) as count FROM admin_users")
        admin_count = admin_cursor.fetchone()['count']
            
        if admin_count == 0:
            default_admin = 'admin'
            default_password = 'admin123'
            hashed_password = bcrypt.hashpw(default_password.encode('utf-8'), bcrypt.gensalt())
            admin_cursor.execute("""
                INSERT INTO admin_users (username, password)
                VALUES (%s, %s)
            """, (default_admin, hashed_password))
            
        admin_conn.commit()
            
    except Error as e:
        print(f"Admin database initialization error: {e}")
    finally:
        if 'admin_cursor' in locals():
            admin_cursor.close()
        if 'admin_conn' in locals():
            admin_conn.close()
        cursor.close()
        root_conn.close()

@app.before_request
def check_access():
    # Skip for these routes
    if request.endpoint in ['login', 'register', 'static', 'admin_login', 'admin_panel']:
        return
        
    if 'user' not in session:
        return redirect(url_for('login'))
        
    # Get user's database info
    db = request.view_args.get('db') if request.view_args else None
    if not db:
        return
        
    DATABASES = get_databases()
    if db not in DATABASES:
        flash('Invalid database', 'danger')
        return redirect(url_for('login'))
        
    # Connect to user's database
    user_conn = connect_db(session['user'], DATABASES[db]['password'], db)
    if not user_conn:
        flash('Database connection failed', 'danger')
        return redirect(url_for('login'))
        
    cursor = user_conn.cursor(dictionary=True)
    try:
        # Check if columns exist
        cursor.execute("SHOW COLUMNS FROM user_settings")
        columns = [col['Field'] for col in cursor.fetchall()]
        
        has_trial_end_date = 'trial_end_date' in columns
        has_subscription_end_date = 'subscription_end_date' in columns
        has_payment_status = 'payment_status' in columns
        
        # Build query based on available columns
        query = """
            SELECT membership_plan, logo_path
            {trial_end_date}
            {subscription_end_date}
            {payment_status}
            FROM user_settings
            WHERE user = %s
        """
        
        trial_end_date_field = ", trial_end_date" if has_trial_end_date else ""
        subscription_end_date_field = ", subscription_end_date" if has_subscription_end_date else ""
        payment_status_field = ", payment_status" if has_payment_status else ""
        
        cursor.execute(query.format(
            trial_end_date=trial_end_date_field,
            subscription_end_date=subscription_end_date_field,
            payment_status=payment_status_field
        ), (session['user'],))
        
        user_settings = cursor.fetchone()
            
        if not user_settings:
            flash('Account settings not found', 'danger')
            return redirect(url_for('login'))
            
        now = datetime.now()
            
        # Check trial status if trial_end_date exists
        if has_trial_end_date and user_settings['membership_plan'] == 'Trial':
            trial_end_date = user_settings.get('trial_end_date')
            if trial_end_date and now > trial_end_date:
                session['trial_expired'] = True
                if request.endpoint != 'account':
                    return redirect(url_for('account', db=db))
            
        # Check subscription status if subscription_end_date exists
        if has_subscription_end_date and has_payment_status:
            if user_settings['payment_status'] != 'active':
                subscription_end_date = user_settings.get('subscription_end_date')
                if subscription_end_date and now > subscription_end_date:
                    session['subscription_expired'] = True
                    if request.endpoint != 'account':
                        return redirect(url_for('account', db=db))
                        
    except Error as e:
        flash(f'Database error: {e}', 'danger')
        return redirect(url_for('login'))
    finally:
        cursor.close()
        user_conn.close()

def migrate_database_schema(user_cursor, db_name):
    """Handle database schema migrations for existing tables"""
    try:
        # Get all tables first
        user_cursor.execute("SHOW TABLES")
        tables = [row[0] for row in user_cursor.fetchall()]
        
        if 'user_settings' not in tables:
            return  # Skip if user_settings doesn't exist

        # Check and add columns to student_information_sheet if table exists
        if 'student_information_sheet' in tables:
            user_cursor.execute("SHOW COLUMNS FROM student_information_sheet LIKE 'scheme'")
            if not user_cursor.fetchone():
                user_cursor.execute("""
                    ALTER TABLE student_information_sheet 
                    ADD COLUMN scheme VARCHAR(100) DEFAULT 'NONE'
                """)
                logger.info(f"Added 'scheme' column to student_information_sheet in {db_name}")

        # Check and add columns to user_settings
        user_cursor.execute("""
            SELECT COLUMN_NAME 
            FROM INFORMATION_SCHEMA.COLUMNS 
            WHERE TABLE_NAME = 'user_settings' 
            AND TABLE_SCHEMA = %s
        """, (db_name,))
        existing_columns = {row[0] for row in user_cursor.fetchall()}
        
        if 'trial_end_date' not in existing_columns:
            user_cursor.execute("""
                ALTER TABLE user_settings 
                ADD COLUMN trial_end_date DATETIME
            """)
            logger.info(f"Added 'trial_end_date' column to user_settings in {db_name}")

        if 'subscription_end_date' not in existing_columns:
            user_cursor.execute("""
                ALTER TABLE user_settings 
                ADD COLUMN subscription_end_date DATETIME
            """)
            logger.info(f"Added 'subscription_end_date' column to user_settings in {db_name}")

        if 'payment_status' not in existing_columns:
            user_cursor.execute("""
                ALTER TABLE user_settings 
                ADD COLUMN payment_status VARCHAR(20) DEFAULT 'inactive'
            """)
            logger.info(f"Added 'payment_status' column to user_settings in {db_name}")

        if 'last_payment_date' not in existing_columns:
            user_cursor.execute("""
                ALTER TABLE user_settings 
                ADD COLUMN last_payment_date DATETIME
            """)
            logger.info(f"Added 'last_payment_date' column to user_settings in {db_name}")

        if 'next_renewal_date' not in existing_columns:
            user_cursor.execute("""
                ALTER TABLE user_settings 
                ADD COLUMN next_renewal_date DATETIME
            """)
            logger.info(f"Added 'next_renewal_date' column to user_settings in {db_name}")

        if 'max_students' not in existing_columns:
            user_cursor.execute("""
                ALTER TABLE user_settings 
                ADD COLUMN max_students INT DEFAULT 2147483647
            """)
            logger.info(f"Added 'max_students' column to user_settings in {db_name}")

        user_cursor.execute("""
            UPDATE user_settings SET max_students = 2147483647
        """)

        # Check and add columns to payment_invoices
        if 'payment_invoices' in tables:
            user_cursor.execute("""
                SELECT COLUMN_NAME 
                FROM INFORMATION_SCHEMA.COLUMNS 
                WHERE TABLE_NAME = 'payment_invoices'
                AND TABLE_SCHEMA = %s
            """, (db_name,))
            payment_invoice_columns = {row[0] for row in user_cursor.fetchall()}

            if 'plan_type' not in payment_invoice_columns:
                user_cursor.execute("""
                    ALTER TABLE payment_invoices
                    ADD COLUMN plan_type VARCHAR(20) DEFAULT NULL
                """)
                logger.info(f"Added 'plan_type' column to payment_invoices in {db_name}")

            if 'invoice_number' not in payment_invoice_columns:
                user_cursor.execute("""
                    ALTER TABLE payment_invoices
                    ADD COLUMN invoice_number VARCHAR(50) DEFAULT NULL
                """)
                logger.info(f"Added 'invoice_number' column to payment_invoices in {db_name}")

    except Error as e:
        logger.error(f"Error during schema migration for {db_name}: {e}")
        raise

def initialize_databases():
    """Initialize all databases with required tables and schema"""
    logger.info("Starting database initialization...")
    
    try:
        # Initialize admin database first
        initialize_admin_database()
        
        # Get list of all databases to initialize
        admin_conn = get_admin_connection()
        if not admin_conn:
            raise Exception("Failed to connect to admin database")
            
        with admin_conn.cursor(dictionary=True) as admin_cursor:
            admin_cursor.execute("""
                SELECT db_name, db_user, db_password, updated_at 
                FROM database_configs
            """)
            databases = {
                row['db_name']: {
                    'user': row['db_user'],
                    'password': row['db_password'],
                    'trial_expires': row['updated_at']
                }
                for row in admin_cursor.fetchall()
            }

        root_conn = get_root_connection()
        if not root_conn:
            raise Exception("Failed to connect as root user")
            
        with root_conn.cursor() as root_cursor:
            for db_name, creds in databases.items():
                try:
                    root_cursor.execute(f"CREATE DATABASE IF NOT EXISTS {db_name}")
                    root_cursor.execute(f"""
                        CREATE USER IF NOT EXISTS '{creds['user']}'@'localhost' 
                        IDENTIFIED BY '{creds['password']}'
                    """)
                    root_cursor.execute(f"""
                        GRANT ALL PRIVILEGES ON {db_name}.* 
                        TO '{creds['user']}'@'localhost'
                    """)
                    logger.info(f"Configured database {db_name} for user {creds['user']}")
                except Error as e:
                    logger.error(f"Error setting up database {db_name}: {e}")
                    raise Exception(f"Database setup failed for {db_name}: {e}")
            root_conn.commit()

        for db_name, creds in databases.items():
            user_conn = None
            try:
                user_conn = connect_db(creds['user'], creds['password'], db_name)
                if not user_conn:
                    raise Exception(f"Failed to connect to database {db_name}")
                with user_conn.cursor() as user_cursor:
                    user_cursor.execute("""
                        CREATE TABLE IF NOT EXISTS student_details (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            enroll_no VARCHAR(50) UNIQUE NOT NULL,
                            course VARCHAR(100) NOT NULL,
                            sex VARCHAR(10),
                            name VARCHAR(100) NOT NULL,
                            father_name VARCHAR(100),
                            mobile_number1 VARCHAR(20),
                            mobile_number2 VARCHAR(20), 
                            address1 VARCHAR(255),
                            address2 VARCHAR(255),
                            city VARCHAR(100),
                            pincode VARCHAR(20),
                            qualification VARCHAR(100),
                            date_of_join DATE,
                            age INT,
                            scheme VARCHAR(100),
                            date_of_birth DATE,
                            concession VARCHAR(100),
                            net_fees DECIMAL(10, 2) DEFAULT 0,
                            total_fees DECIMAL(10, 2) DEFAULT 0,
                            fees DECIMAL(10, 2) DEFAULT 0,
                            balance_fees DECIMAL(10, 2) DEFAULT 0,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            updated_at DATETIME
                        )
                    """)
                    user_cursor.execute("""
                        CREATE TABLE IF NOT EXISTS fee_payments (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            enroll_no VARCHAR(50) NOT NULL,
                            fee_amount DECIMAL(10, 2) NOT NULL,
                            bill_number VARCHAR(50) NOT NULL,
                            payment_date DATETIME NOT NULL,
                            FOREIGN KEY (enroll_no) REFERENCES student_details(enroll_no) ON DELETE CASCADE
                        )
                    """)
                    user_cursor.execute("""
                        CREATE TABLE IF NOT EXISTS student_information_sheet (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            sno VARCHAR(50),
                            name VARCHAR(100) NOT NULL,
                            father_name VARCHAR(100),
                            mobile_number1 VARCHAR(20),
                            mobile_number2 VARCHAR(20),
                            employment_status VARCHAR(100),
                            address VARCHAR(255),
                            pin_code VARCHAR(20),
                            sex VARCHAR(10),
                            qualification VARCHAR(100),
                            reason TEXT,
                            course_interested VARCHAR(100),
                            joining_plan VARCHAR(100),
                            source_info TEXT,
                            scheme VARCHAR(100) DEFAULT 'NONE',
                            status VARCHAR(20) DEFAULT 'Pending',
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            updated_at DATETIME
                        )
                    """)
                    user_cursor.execute("""
                        CREATE TABLE IF NOT EXISTS user_settings (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            user VARCHAR(50) NOT NULL,
                            membership_plan VARCHAR(50) DEFAULT 'Trial',
                            membership_payment DECIMAL(10, 2) DEFAULT 0.00,
                            logo_path VARCHAR(255) DEFAULT 'image/logo.png',
                            trial_start_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                            trial_end_date DATETIME,
                            subscription_start_date DATETIME,
                            subscription_end_date DATETIME,
                            payment_status VARCHAR(20) DEFAULT 'inactive',
                            last_payment_date DATETIME,
                            next_renewal_date DATETIME,
                            max_students INT DEFAULT 2147483647,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            updated_at DATETIME,
                            UNIQUE (user)
                        )
                    """)
                    user_cursor.execute("""
                        CREATE TABLE IF NOT EXISTS payment_invoices (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            user VARCHAR(50) NOT NULL,
                            order_id VARCHAR(100) NOT NULL,
                            payment_id VARCHAR(100),
                            amount DECIMAL(10, 2) NOT NULL,
                            status VARCHAR(20) NOT NULL,
                            plan_type VARCHAR(20) DEFAULT NULL,
                            invoice_number VARCHAR(50) DEFAULT NULL,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )
                    """)
                    migrate_database_schema(user_cursor, db_name)
                    if creds.get('trial_expires'):
                        user_cursor.execute("""
                            INSERT INTO user_settings (
                                user, membership_plan, membership_payment, 
                                logo_path, trial_end_date, updated_at
                            ) VALUES (%s, %s, %s, %s, %s, %s)
                            ON DUPLICATE KEY UPDATE
                                membership_plan = VALUES(membership_plan),
                                membership_payment = VALUES(membership_payment),
                                trial_end_date = VALUES(trial_end_date),
                                updated_at = VALUES(updated_at)
                        """, (
                            creds['user'],
                            'Trial',
                            0.00,
                            'image/logo.png',
                            creds['trial_expires'],
                            datetime.now()
                        ))
                    user_conn.commit()
                    logger.info(f"Successfully initialized database: {db_name}")
            except Error as e:
                logger.error(f"Error initializing database {db_name}: {e}")
                if user_conn:
                    user_conn.rollback()
                raise
            finally:
                if user_conn:
                    user_conn.close()
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        raise
    finally:
        if 'admin_conn' in locals() and admin_conn:
            admin_conn.close()
        if 'root_conn' in locals() and root_conn:
            root_conn.close()

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
        
    data = request.form
    email = data.get('email')
    username = data.get('username')
    password = data.get('password')
    confirm_password = data.get('confirm_password')
    membership_plan = data.get('membership_plan', 'monthly')
        
    # Validate input
    if not all([email, username, password, confirm_password]):
        return jsonify({'success': False, 'message': 'All fields are required'}), 400
        
    if password != confirm_password:
        return jsonify({'success': False, 'message': 'Passwords do not match'}), 400
        
    if len(password) < 8:
        return jsonify({'success': False, 'message': 'Password must be at least 8 characters'}), 400
        
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return jsonify({'success': False, 'message': 'Invalid email format'}), 400
        
    admin_conn = get_admin_connection()
    if not admin_conn:
        return jsonify({'success': False, 'message': 'Database connection failed'}), 500
        
    cursor = admin_conn.cursor(dictionary=True)
    try:
        # First check if username already exists
        cursor.execute("SELECT db_user FROM database_configs WHERE db_user = %s", (username,))
        if cursor.fetchone():
            return jsonify({'success': False, 'message': 'Username already exists. Please choose a different username.'}), 400

        # Create database configuration
        db_name = f"db_{username}"
        db_password = password
            
        # Calculate trial expiration (7 days from now)
        trial_start = datetime.now()
        trial_end = trial_start + timedelta(days=7)

        # Insert into database_configs
        cursor.execute("""
            INSERT INTO database_configs (db_name, db_user, db_password, updated_at)
            VALUES (%s, %s, %s, %s)
        """, (db_name, username, db_password, trial_end))
        
        admin_conn.commit()  # <-- THIS LINE IS ESSENTIAL FOR TABLE CREATION

        # Create MySQL user and database
        root_conn = get_root_connection()
        if not root_conn:
            admin_conn.rollback()
            return jsonify({'success': False, 'message': 'Failed to create database'}), 500
                
        root_cursor = root_conn.cursor()
        try:
            # Create database
            root_cursor.execute(f"CREATE DATABASE IF NOT EXISTS {db_name}")
                
            # Create user if not exists and grant privileges
            root_cursor.execute(f"CREATE USER IF NOT EXISTS '{username}'@'localhost' IDENTIFIED BY '{password}'")
            root_cursor.execute(f"GRANT ALL PRIVILEGES ON {db_name}.* TO '{username}'@'localhost'")
            root_cursor.execute("FLUSH PRIVILEGES")
            root_conn.commit()
        except Error as e:
            root_conn.rollback()
            admin_conn.rollback()
            return jsonify({'success': False, 'message': f'MySQL user creation failed: {str(e)}'}), 500
        finally:
            root_cursor.close()
            root_conn.close()
            
        # Initialize the database tables for all users (including the new one)
        try:
            initialize_databases()
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
            admin_conn.rollback()
            return jsonify({'success': False, 'message': 'Database setup failed. Please contact support.'}), 500
            
        # Create/update user_settings record (just update, since row was inserted in initialize_databases)
        user_conn = connect_db(username, password, db_name)
        if not user_conn:
            admin_conn.rollback()
            return jsonify({'success': False, 'message': 'Failed to initialize user settings'}), 500
                
        user_cursor = user_conn.cursor()
        try:
            membership_payment = 699.00 if membership_plan == 'monthly' else 7999.00

            # Update the user_settings row (already created in initialize_databases)
            user_cursor.execute("""
                UPDATE user_settings 
                SET membership_plan = %s,
                    membership_payment = %s,
                    logo_path = %s,
                    trial_start_date = %s,
                    trial_end_date = %s,
                    payment_status = %s,
                    updated_at = %s
                WHERE user = %s
            """, (
                'Trial',
                membership_payment,
                'image/logo.png',
                trial_start,
                trial_end,
                'active',  # Trial is active
                datetime.now(),
                username
            ))

            user_cursor.execute("""
                INSERT INTO payment_invoices (user, order_id, payment_id, amount, status)
                VALUES (%s, %s, %s, %s, %s)
            """, (
                username,
                f"TRIAL-{uuid.uuid4().hex[:8]}",
                "TRIAL",
                0.00,
                "success"
            ))
                
            user_conn.commit()
            admin_conn.commit()  # Only commit admin changes after everything else succeeds
                
            return jsonify({
                'success': True, 
                'message': 'Registration successful',
                'redirect': url_for('login')
            })
                
        except Error as e:
            user_conn.rollback()
            admin_conn.rollback()
            return jsonify({'success': False, 'message': f'Error creating user settings: {str(e)}'}), 500
        finally:
            user_cursor.close()
            if user_conn:
                user_conn.close()
                
    except Error as e:
        admin_conn.rollback()
        return jsonify({'success': False, 'message': f'Database error: {str(e)}'}), 500
    finally:
        cursor.close()
        admin_conn.close()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        DATABASES = get_databases()
            
        for db_name, creds in DATABASES.items():
            if username == creds['user'] and password == creds['password']:
                # Check trial expiration
                admin_conn = get_admin_connection()
                if admin_conn:
                    cursor = admin_conn.cursor(dictionary=True)
                    try:
                        cursor.execute("""
                            SELECT updated_at FROM database_configs 
                            WHERE db_user = %s
                        """, (username,))
                        config = cursor.fetchone()
                            
                        if config and config['updated_at']:
                            trial_expires = config['updated_at']
                            if datetime.now() > trial_expires:
                                session['trial_expired'] = True
                                session['user'] = username
                                return redirect(url_for('account', db=db_name))
                    except Error as e:
                        logger.error(f"Error checking trial period for {username}: {e}")
                    finally:
                        cursor.close()
                        admin_conn.close()
                    
                else:
                    logger.error(f"Failed to connect to admin database for user {username}")
                    flash('Failed to connect to admin database', 'danger')
                    return render_template('authentication/login.html')
                    
                session['user'] = username
                session['password'] = password
                session.permanent = True
                return redirect(url_for('user_dashboard', db=db_name))
            
        flash('Invalid login credentials', 'danger')
    return render_template('authentication/login.html')

def validate_schema(connection):
    required_columns = {
        'user_settings': ['payment_status', 'last_payment_date', 'next_renewal_date'],
        'payment_invoices': ['plan_type', 'invoice_number']
    }
        
    cursor = connection.cursor()
    for table, columns in required_columns.items():
        cursor.execute(f"SHOW COLUMNS FROM {table}")
        existing_columns = [col[0] for col in cursor.fetchall()]  # 👈 using index now
        for col in columns:
            if col not in existing_columns:
                raise Exception(f"Missing column '{col}' in table '{table}'")
    cursor.close()

from datetime import datetime, timedelta
from flask import render_template, session, redirect, url_for, flash, request, jsonify, send_file
import pdfkit
from io import BytesIO

from datetime import datetime, timedelta
from flask import Flask, session, flash, redirect, url_for, render_template
from mysql.connector import Error

@app.route('/account/<db>', methods=['GET'])
def account(db):
    if not session.get('user'):
        flash('Session expired. Please log in again.', 'warning')
        return redirect(url_for('login'))
        
    DATABASES = get_databases()
    if db not in DATABASES:
        flash('Invalid database', 'danger')
        return redirect(url_for('login'))
        
    connection = connect_db(session['user'], DATABASES[db]['password'], db)
    validate_schema(connection)
    if not connection:
        flash('Failed to connect to the database', 'danger')
        return redirect(url_for('login'))
        
    cursor = connection.cursor(dictionary=True)
    try:
        # Check if payment_status column exists
        cursor.execute("SHOW COLUMNS FROM user_settings LIKE 'payment_status'")
        has_payment_status = cursor.fetchone() is not None
            
        # Build query based on whether column exists
        if has_payment_status:
            cursor.execute("""
                SELECT membership_plan, membership_payment, logo_path, updated_at, 
                    payment_status, last_payment_date, next_renewal_date
                FROM user_settings
                WHERE user = %s
            """, (session['user'],))
        else:
            cursor.execute("""
                SELECT membership_plan, membership_payment, logo_path, updated_at,
                    last_payment_date, next_renewal_date
                FROM user_settings
                WHERE user = %s
            """, (session['user'],))
                
        user_info = cursor.fetchone() or {
            'membership_plan': 'Trial',
            'membership_payment': 0.00,
            'logo_path': 'image/logo.png',
            'updated_at': None,
            'payment_status': 'inactive',
            'last_payment_date': None,
            'next_renewal_date': None
        }
            
        # If payment_status wasn't in the query, add default value
        if not has_payment_status:
            user_info['payment_status'] = 'inactive'
            
        # Ensure datetime format for updated_at
        if user_info['updated_at'] and isinstance(user_info['updated_at'], str):
            try:
                user_info['updated_at'] = datetime.strptime(user_info['updated_at'], '%Y-%m-%d %H:%M:%S')
            except ValueError:
                user_info['updated_at'] = None

        # Trial period logic – 7 days from updated_at or today
        if not user_info['updated_at']:
            user_info['trial_end_date'] = datetime.now() + timedelta(days=7)
        else:
            user_info['trial_end_date'] = user_info['updated_at'] + timedelta(days=7)

        # Calculate membership status
        current_date = datetime.now()
        if user_info['next_renewal_date']:
            try:
                next_renewal = user_info['next_renewal_date'] if isinstance(user_info['next_renewal_date'], datetime) \
                    else datetime.strptime(user_info['next_renewal_date'], '%Y-%m-%d %H:%M:%S')
                days_remaining = (next_renewal - current_date).days
                
                if days_remaining < 0:
                    user_info['membership_status'] = 'expired'
                    user_info['days_remaining'] = 0
                elif days_remaining <= 7:
                    user_info['membership_status'] = 'expiring_soon'
                    user_info['days_remaining'] = days_remaining
                else:
                    user_info['membership_status'] = 'active'
                    user_info['days_remaining'] = days_remaining
            except Exception as e:
                user_info['membership_status'] = 'trial'
                user_info['days_remaining'] = 0
        else:
            user_info['next_renewal_date'] = 'Not set'
            user_info['membership_status'] = 'trial'
            user_info['days_remaining'] = (user_info['trial_end_date'] - current_date).days if user_info['trial_end_date'] else 0
            
        # Get payment history
        cursor.execute("""
            SELECT id, order_id, payment_id, amount, status, 
                created_at, plan_type, invoice_number
            FROM payment_invoices
            WHERE user = %s
            ORDER BY created_at DESC
        """, (session['user'],))
        invoices = cursor.fetchall()
            
        logo_path = get_logo_path(db, session['user'])
            
        return render_template('account.html',
                            db=db,
                            user=session['user'],
                            user_info=user_info,
                            invoices=invoices,
                            logo_path=logo_path,
                            now=current_date)
    except Error as e:
        flash(f'Database error: {str(e)}', 'danger')
        return redirect(url_for('user_dashboard', db=db))
    finally:
        cursor.close()
        connection.close()

@app.route('/payment_verify/<db>', methods=['POST'])
def payment_verify(db):
    if not session.get('user'):
        return jsonify({'success': False, 'message': 'Session expired'}), 401

    payment_id = request.form.get('razorpay_payment_id')
    order_id = request.form.get('razorpay_order_id')
    signature = request.form.get('razorpay_signature')
    plan = request.form.get('plan')

    if not all([payment_id, order_id, signature, plan]):
        return jsonify({'success': False, 'message': 'Missing payment details'}), 400

    try:
        # 🔐 Verify payment with Razorpay
        razorpay_client.utility.verify_payment_signature({
            'razorpay_order_id': order_id,
            'razorpay_payment_id': payment_id,
            'razorpay_signature': signature
        })

        DATABASES = get_databases()
        if db not in DATABASES:
            return jsonify({'success': False, 'message': 'Invalid database'}), 400

        connection = connect_db(session['user'], DATABASES[db]['password'], db)
        if not connection:
            return jsonify({'success': False, 'message': 'Database connection failed'}), 500

        cursor = connection.cursor()

        # 🧪 Check if `payment_status` column exists (for backward compatibility)
        cursor.execute("SHOW COLUMNS FROM user_settings LIKE 'payment_status'")
        has_payment_status = cursor.fetchone() is not None

        # 💰 Determine amount and renewal date
        amount = 699.00 if plan == 'monthly' else 7999.00
        now = datetime.now()
        renewal = now + timedelta(days=30 if plan == 'monthly' else 365)

        # 🧾 Generate invoice number
        invoice_number = f"INV-{now.strftime('%Y%m%d')}-{payment_id[:6].upper()}"

        # 🛠️ Update user_settings with or without 'payment_status'
        if has_payment_status:
            cursor.execute("""
                UPDATE user_settings
                SET membership_plan = %s,
                    membership_payment = %s,
                    payment_status = 'active',
                    last_payment_date = %s,
                    next_renewal_date = %s,
                    updated_at = %s
                WHERE user = %s
            """, (
                'Monthly' if plan == 'monthly' else 'Yearly',
                amount,
                now,
                renewal,
                now,
                session['user']
            ))
        else:
            cursor.execute("""
                UPDATE user_settings
                SET membership_plan = %s,
                    membership_payment = %s,
                    last_payment_date = %s,
                    next_renewal_date = %s,
                    updated_at = %s
                WHERE user = %s
            """, (
                'Monthly' if plan == 'monthly' else 'Yearly',
                amount,
                now,
                renewal,
                now,
                session['user']
            ))

        # 🧾 Record invoice in payment_invoices
        cursor.execute("""
            INSERT INTO payment_invoices 
            (user, order_id, payment_id, amount, status, plan_type, invoice_number, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            session['user'],
            order_id,
            payment_id,
            amount,
            'success',
            'Monthly' if plan == 'monthly' else 'Yearly',
            invoice_number,
            now
        ))

        connection.commit()

        return jsonify({
            'success': True,
            'message': 'Payment verified and membership updated!',
            'invoice_number': invoice_number
        })

    except Exception as e:
        if 'connection' in locals() and connection:
            connection.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'connection' in locals():
            connection.close()

@app.route('/download_invoice/<db>/<invoice_id>')
def download_invoice(db, invoice_id):
    if not session.get('user'):
        flash('Session expired. Please log in again.', 'warning')
        return redirect(url_for('login'))
        
    DATABASES = get_databases()
    if db not in DATABASES:
        flash('Invalid database', 'danger')
        return redirect(url_for('login'))
        
    connection = connect_db(session['user'], DATABASES[db]['password'], db)
    if not connection:
        flash('Failed to connect to the database', 'danger')
        return redirect(url_for('login'))
        
        cursor = connection.cursor(dictionary=True)
        try:
            # Get invoice details
            cursor.execute("""
                SELECT pi.*, us.membership_plan, us.logo_path
                FROM payment_invoices pi
                JOIN user_settings us ON pi.user = us.user
                WHERE pi.id = %s AND pi.user = %s
            """, (invoice_id, session['user']))
            
            invoice = cursor.fetchone()
            if not invoice:
                flash('Invoice not found', 'danger')
                return redirect(url_for('account', db=db))
            
            # Render HTML invoice
            invoice_html = render_template('invoice_template.html',
                                        invoice=invoice,
                                        user=session['user'],
                                        db=db)
            
            # Generate PDF
            pdf = pdfkit.from_string(invoice_html, False, options={
                'page-size': 'A4',
                'margin-top': '0.5in',
                'margin-right': '0.5in',
                'margin-bottom': '0.5in',
                'margin-left': '0.5in',
                'encoding': 'UTF-8',
            })
            
            # Send PDF as download
            return send_file(
                BytesIO(pdf),
                as_attachment=True,
                download_name=f"Invoice_{invoice['invoice_number']}.pdf",
                mimetype='application/pdf'
            )
        except Exception as e:
            flash(f'Error generating invoice: {str(e)}', 'danger')
            return redirect(url_for('account', db=db))
        finally:
            cursor.close()
            connection.close()

@app.route('/logo_upload/<db>', methods=['GET', 'POST'])
def logo_upload(db):
    user = session.get('user')
    if not user:
        flash('Session expired. Please log in again.', 'warning')
        return redirect(url_for('login'))
    
    DATABASES = get_databases()
    if db not in DATABASES:
        flash('Invalid database', 'danger')
        return redirect(url_for('login'))
    
    connection = connect_db(user, DATABASES[db]['password'], db)
    if not connection:
        flash('Failed to connect to the database', 'danger')
        return redirect(url_for('login'))
    
    cursor = connection.cursor(dictionary=True)
    try:
        if request.method == 'POST':
            if 'photo' not in request.files:
                flash('No file uploaded', 'danger')
                return redirect(url_for('logo_upload', db=db))
            
            file = request.files['photo']
            if file.filename == '':
                flash('No file selected', 'danger')
                return redirect(url_for('logo_upload', db=db))
            
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                unique_filename = f"{uuid.uuid4().hex}_{filename}"
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                file.save(file_path)
                logo_path = f"image/{unique_filename}"
                
                cursor.execute("""
                    INSERT INTO user_settings (user, logo_path, updated_at)
                    VALUES (%s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                    logo_path = %s,
                    updated_at = %s
                """, (
                    user, logo_path, datetime.now(),
                    logo_path, datetime.now()
                ))
                connection.commit()
                flash('Logo uploaded successfully', 'success')
                return redirect(url_for('user_dashboard', db=db))
            else:
                flash('Invalid file format. Allowed formats: png, jpg, jpeg, gif', 'danger')
                return redirect(url_for('logo_upload', db=db))
        
        # Fetch current logo for display
        cursor.execute("SELECT logo_path FROM user_settings WHERE user = %s", (user,))
        user_settings = cursor.fetchone()
        logo_path = user_settings['logo_path'] if user_settings and user_settings['logo_path'] else 'image/logo.png'
        
        return render_template('logo_upload.html', db=db, logo_path=logo_path)
    
    except Error as e:
        flash(f'Database error: {str(e)}', 'danger')
        return redirect(url_for('user_dashboard', db=db))
    finally:
        cursor.close()
        connection.close()

@app.route('/analytics_dashboard/<db>')
def analytics_dashboard(db):
    user = session.get('user')
    if not user:
        flash('Session expired. Please log in again.', 'warning')
        return redirect(url_for('login'))

    DATABASES = get_databases()
    if db not in DATABASES:
        flash('Invalid database', 'danger')
        return redirect(url_for('login'))

    # Get period and custom date range parameters
    period = request.args.get('period', 'week')
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')

    # Connect to database
    connection = connect_db(user, DATABASES[db]['password'], db)
    if not connection:
        flash('Failed to connect to the database', 'danger')
        return redirect(url_for('login'))

    cursor = connection.cursor(dictionary=True)
    try:
        # Initialize date range variables
        today = date.today()
        start_date = None
        end_date = today
        date_range_display = ""
        date_condition = ""
        fee_date_condition = ""
        params = []

        # Handle custom date range if provided
        if start_date_str and end_date_str:
            try:
                start_date = date.fromisoformat(start_date_str)
                end_date = date.fromisoformat(end_date_str)
                if start_date > end_date:
                    flash('Start date cannot be after end date', 'danger')
                    return redirect(url_for('analytics_dashboard', db=db, period=period))
                date_range_display = f"{start_date.strftime('%d %b %Y')} to {end_date.strftime('%d %b %Y')}"
                date_condition = "WHERE date_of_join BETWEEN %s AND %s"
                fee_date_condition = "AND payment_date BETWEEN %s AND %s"
                params = [start_date, end_date]
                period = 'custom'  # Override period to indicate custom range
            except ValueError:
                flash('Invalid date format', 'danger')
                return redirect(url_for('analytics_dashboard', db=db, period=period))
        else:
            # Determine date range based on period
            if period == 'week':
                start_date = today - timedelta(days=today.weekday())
                date_range_display = f"{start_date.strftime('%d %b %Y')} to {end_date.strftime('%d %b %Y')}"
                date_condition = "WHERE date_of_join BETWEEN %s AND %s"
                fee_date_condition = "AND payment_date BETWEEN %s AND %s"
                params = [start_date, end_date]
            elif period == 'month':
                start_date = today.replace(day=1)
                date_range_display = f"{start_date.strftime('%d %b %Y')} to {end_date.strftime('%d %b %Y')}"
                date_condition = "WHERE date_of_join BETWEEN %s AND %s"
                fee_date_condition = "AND payment_date BETWEEN %s AND %s"
                params = [start_date, end_date]
            elif period == 'year':
                start_date = date(today.year, 1, 1)
                date_range_display = f"{start_date.strftime('%d %b %Y')} to {end_date.strftime('%d %b %Y')}"
                date_condition = "WHERE date_of_join BETWEEN %s AND %s"
                fee_date_condition = "AND payment_date BETWEEN %s AND %s"
                params = [start_date, end_date]
            elif period == 'joined':
                date_range_display = "All Joined Students"
                date_condition = ""
                fee_date_condition = ""
                params = []
            elif period == 'not_joined':
                date_range_display = "Not Joined Students"
                date_condition = ""
                fee_date_condition = ""
                params = []
            else:
                flash('Invalid period selected', 'danger')
                return redirect(url_for('analytics_dashboard', db=db, period='week'))

        # Initialize data structures
        total_students = 0
        active_learners = 0
        inactive_learners = 0
        fully_paid_count = 0
        pending_count = 0
        total_revenue = 0.0
        collected_revenue = 0.0
        pending_payments = 0.0
        course_counts = {}
        course_performance = []
        enrollment_trends = []
        not_joined_students = []

        # Log query parameters for debugging
        logger.debug(f"Period: {period}, Start Date: {start_date}, End Date: {end_date}, Params: {params}")

        # Fetch total students count
        query = f"SELECT COUNT(*) as total_students FROM student_details {date_condition}"
        cursor.execute(query, params)
        total_students = cursor.fetchone()['total_students'] or 0
        logger.debug(f"Total Students: {total_students}")

        # Fetch active learners (students with activity in date range)
        if period != 'not_joined':
            query = f"""
                SELECT COUNT(DISTINCT enroll_no) as active_learners
                FROM student_details
                {date_condition}
                {"OR EXISTS (" if date_condition else "WHERE EXISTS ("}
                    SELECT 1 FROM fee_payments fp
                    WHERE fp.enroll_no = student_details.enroll_no
                    {fee_date_condition}
                )
            """
            cursor.execute(query, params * 2 if fee_date_condition else params)
            active_learners = cursor.fetchone()['active_learners'] or 0
            inactive_learners = total_students - active_learners
            logger.debug(f"Active Learners: {active_learners}, Inactive: {inactive_learners}")
        else:
            active_learners = 0
            inactive_learners = 0

        # Fetch course counts
        query = f"""
            SELECT course, COUNT(*) as count
            FROM student_details
            {date_condition}
            GROUP BY course
        """
        cursor.execute(query, params)
        course_counts = {row['course'] or 'Unknown': row['count'] for row in cursor.fetchall()}
        total_courses = len(course_counts)
        logger.debug(f"Course Counts: {course_counts}")

        # Fetch payment status counts
        query = f"""
            SELECT 
                SUM(CASE WHEN balance_fees = 0 THEN 1 ELSE 0 END) as fully_paid,
                SUM(CASE WHEN balance_fees > 0 THEN 1 ELSE 0 END) as pending
            FROM student_details
            {date_condition}
        """
        cursor.execute(query, params)
        payment_status = cursor.fetchone()
        fully_paid_count = payment_status['fully_paid'] or 0
        pending_count = payment_status['pending'] or 0
        logger.debug(f"Fully Paid: {fully_paid_count}, Pending: {pending_count}")

        # Fetch revenue data
        query = f"""
            SELECT 
                COALESCE(SUM(total_fees), 0) as total_revenue,
                COALESCE(SUM(fees), 0) as collected_revenue
            FROM student_details
            {date_condition}
        """
        cursor.execute(query, params)
        revenue_data = cursor.fetchone()
        total_revenue = float(revenue_data['total_revenue'] or 0)
        collected_revenue = float(revenue_data['collected_revenue'] or 0)
        pending_payments = total_revenue - collected_revenue
        logger.debug(f"Total Revenue: {total_revenue}, Collected: {collected_revenue}, Pending: {pending_payments}")

        # Fetch course performance
        query = f"""
            SELECT 
                sd.course,
                COUNT(DISTINCT sd.enroll_no) as total_students,
                COALESCE(SUM(fp.fee_amount), 0) as total_fees
            FROM student_details sd
            LEFT JOIN fee_payments fp ON sd.enroll_no = fp.enroll_no
                {fee_date_condition}
            {date_condition.replace('WHERE', 'AND') if date_condition else 'WHERE 1=1'}
            GROUP BY sd.course
            ORDER BY total_fees DESC
        """
        cursor.execute(query, params * 2 if fee_date_condition else params)
        course_performance = [
            {
                'course': row['course'] or 'Unknown',
                'total_students': int(row['total_students'] or 0),
                'total_fees': float(row['total_fees'] or 0)
            } for row in cursor.fetchall()
        ]
        logger.debug(f"Course Performance: {course_performance}")

        # Fetch enrollment trends
        if period != 'not_joined':
            query = f"""
                SELECT 
                    DATE_FORMAT(date_of_join, '%Y-%m-%d') as date, 
                    COUNT(*) as new_enrollments,
                    COALESCE(SUM(total_fees), 0) as daily_revenue
                FROM student_details
                {date_condition}
                GROUP BY DATE_FORMAT(date_of_join, '%Y-%m-%d')
                ORDER BY date
            """
            cursor.execute(query, params)
            enrollment_trends = [
                {
                    'date': row['date'],
                    'new_enrollments': int(row['new_enrollments'] or 0),
                    'revenue': float(row['daily_revenue'] or 0)
                } for row in cursor.fetchall()
            ]
        logger.debug(f"Enrollment Trends: {enrollment_trends}")

        # Fetch not joined students with both mobile numbers
        if period == 'not_joined':
            cursor.execute("SHOW TABLES LIKE 'student_information_sheet'")
            if cursor.fetchone():
                cursor.execute("""
                    SELECT id, name, course_interested, mobile_number1, mobile_number2, status, created_at
                    FROM student_information_sheet
                    WHERE status != 'Joined' OR status IS NULL
                    ORDER BY created_at DESC
                """)
                not_joined_students = [
                    {
                        'id': row['id'],
                        'name': row['name'] or '',
                        'course_interested': row['course_interested'] or '',
                        'mobile_number1': row['mobile_number1'] or '',
                        'mobile_number2': row['mobile_number2'] or '',
                        'status': row['status'] or 'Pending',
                        'created_at': row['created_at']
                    } for row in cursor.fetchall()
                ]
                logger.debug(f"Not Joined Students: {not_joined_students}")

        # Get top course by fees and enrollments
        max_fee_course = max(course_performance, key=lambda x: x['total_fees'], default={'course': 'None', 'total_fees': 0})
        max_student_course = max(course_performance, key=lambda x: x['total_students'], default={'course': 'None', 'total_students': 0})

        logo_path = get_logo_path(db, user)

        return render_template(
            'analytics_dashboard.html',
            db=db,
            user=user,
            total_students=total_students,
            total_courses=total_courses,
            active_learners=active_learners,
            inactive_learners=inactive_learners,
            fully_paid_count=fully_paid_count,
            pending_count=pending_count,
            total_revenue=total_revenue,
            collected_revenue=collected_revenue,
            pending_payments=pending_payments,
            course_performance=course_performance,
            course_enrollment=course_counts,
            enrollment_trends=enrollment_trends,
            logo_path=logo_path,
            period=period,
            date_range_display=date_range_display,
            max_fee_course=max_fee_course['course'],
            max_fee_amount=max_fee_course['total_fees'],
            max_student_course=max_student_course['course'],
            max_student_count=max_student_course['total_students'],
            not_joined_students=not_joined_students,
            today=today,
            start_date=start_date_str or start_date,  # Pass start_date for form
 jede= end_date_str or end_date  # Pass end_date for form
        )

    except Exception as e:
        logger.error(f"Error in analytics_dashboard: {str(e)}")
        flash(f"Failed to fetch analytics data: {e}", 'danger')
        return redirect(url_for('user_dashboard', db=db))
    finally:
        cursor.close()
        connection.close()

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        admin_conn = get_admin_connection()
        if admin_conn:
            cursor = admin_conn.cursor(dictionary=True)
            try:
                cursor.execute("SELECT username, password FROM admin_users WHERE username = %s", (username,))
                admin = cursor.fetchone()
                if admin and bcrypt.checkpw(password.encode('utf-8'), admin['password'].encode('utf-8')):
                    session['admin'] = username
                    session.permanent = True
                    return redirect(url_for('admin_panel'))
                else:
                    flash('Invalid admin credentials', 'danger')
            except Error as e:
                flash(f'Database error: {e}', 'danger')
            finally:
                cursor.close()
                admin_conn.close()
        else:
            flash('Failed to connect to admin database', 'danger')
    return render_template('admin/login.html')

@app.route('/admin/panel', methods=['GET', 'POST'])
def admin_panel():
    if 'admin' not in session:
        flash('Please login as admin', 'warning')
        return redirect(url_for('admin_login'))
    
    admin_conn = get_admin_connection()
    if not admin_conn:
        flash('Failed to connect to admin database', 'danger')
        return redirect(url_for('admin_login'))
    
    cursor = admin_conn.cursor(dictionary=True)
    try:
        if request.method == 'POST':
            action = request.form.get('action')
            db_name = request.form.get('db_name')
            db_user = request.form.get('db_user')
            db_password = request.form.get('db_password')
            config_id = request.form.get('config_id')
            membership_plan = request.form.get('membership_plan')
            membership_payment = request.form.get('membership_payment', '0.00')
            updated_at = datetime.now()
            
            try:
                membership_payment = float(membership_payment)
                if membership_payment < 0:
                    flash('Membership payment cannot be negative', 'danger')
                    return redirect(url_for('admin_panel'))
            except ValueError:
                flash('Invalid membership payment amount', 'danger')
                return redirect(url_for('admin_panel'))
            
            if action == 'add':
                if not all([db_name, db_user, db_password, membership_plan, membership_payment]):
                    flash('All fields are required', 'danger')
                else:
                    try:
                        cursor.execute("""
                            INSERT INTO database_configs (db_name, db_user, db_password, updated_at)
                            VALUES (%s, %s, %s, %s)
                        """, (db_name, db_user, db_password, updated_at))
                        admin_conn.commit()
                        flash('Database configuration added successfully', 'success')
                        initialize_databases()
                        
                        user_conn = connect_db(db_user, db_password, db_name)
                        if user_conn:
                            user_cursor = user_conn.cursor()
                            try:
                                user_cursor.execute("""
                                    INSERT INTO user_settings (user, membership_plan, membership_payment, logo_path, updated_at, created_at)
                                    VALUES (%s, %s, %s, %s, %s, %s)
                                    ON DUPLICATE KEY UPDATE
                                    membership_plan = %s,
                                    membership_payment = %s,
                                    updated_at = %s
                                """, (
                                    db_user, membership_plan, membership_payment, 'image/logo.png', updated_at, updated_at,
                                    membership_plan, membership_payment, updated_at
                                ))
                                user_conn.commit()
                            except Error as e:
                                flash(f'Error initializing user settings: {e}', 'danger')
                            finally:
                                user_cursor.close()
                                user_conn.close()
                        else:
                            flash(f'Error adding configuration: {e}', 'danger')
                    except Error as e:
                        flash(f'Error adding configuration: {e}', 'danger')
            
            elif action == 'update':
                if not all([config_id, db_name, db_user, db_password, membership_plan, membership_payment]):
                    flash('All fields are required', 'danger')
                else:
                    try:
                        cursor.execute("""
                            UPDATE database_configs
                            SET db_name = %s, db_user = %s, db_password = %s, updated_at = %s
                            WHERE id = %s
                        """, (db_name, db_user, db_password, updated_at, config_id))
                        admin_conn.commit()
                        flash('Database configuration updated successfully', 'success')
                        initialize_databases()
                        
                        user_conn = connect_db(db_user, db_password, db_name)
                        if user_conn:
                            user_cursor = user_conn.cursor()
                            try:
                                user_cursor.execute("""
                                    INSERT INTO user_settings (user, membership_plan, membership_payment, logo_path, updated_at, created_at)
                                    VALUES (%s, %s, %s, %s, %s, %s)
                                    ON DUPLICATE KEY UPDATE
                                    membership_plan = %s,
                                    membership_payment = %s,
                                    updated_at = %s
                                """, (
                                    db_user, membership_plan, membership_payment, 'image/logo.png', updated_at, updated_at,
                                    membership_plan, membership_payment, updated_at
                                ))
                                user_conn.commit()
                            except Error as e:
                                flash(f'Error updating user settings: {e}', 'danger')
                            finally:
                                user_cursor.close()
                                user_conn.close()
                    except Error as e:
                        flash(f'Error updating configuration: {e}', 'danger')
            
            elif action == 'delete':
                try:
                    cursor.execute("DELETE FROM database_configs WHERE id = %s", (config_id,))
                    admin_conn.commit()
                    flash('Database configuration deleted successfully', 'success')
                except Error as e:
                    flash(f'Error deleting configuration: {e}', 'danger')
        
        # ✅ Use your desired SELECT logic here (with LEFT JOIN for user_settings)
        cursor.execute("""
    SELECT id, db_name, db_user, db_password, updated_at as trial_end_date
    FROM database_configs
""")
        configs = cursor.fetchall()
        now = datetime.now()
        
        return render_template('admin/panel.html', configs=configs, now=now)
    
    finally:
        cursor.close()
        admin_conn.close()
        
@app.route('/admin/user/<db>/<user>')
def admin_user_details(db, user):
    if 'admin' not in session:
        flash('Please login as admin', 'warning')
        return redirect(url_for('admin_login'))
    
    DATABASES = get_databases()
    if db not in DATABASES:
        flash('Invalid database', 'danger')
        return redirect(url_for('admin_login'))
    
    # Connect to the user's database
    user_conn = connect_db(user, DATABASES[db]['password'], db)
    if not user_conn:
        flash('Failed to connect to user database', 'danger')
        return redirect(url_for('admin_panel'))
    
    cursor = user_conn.cursor(dictionary=True)
    try:
        # Get user settings
        cursor.execute("""
            SELECT * FROM user_settings WHERE user = %s
        """, (user,))
        user_settings = cursor.fetchone()
        
        # Get payment history
        cursor.execute("""
            SELECT * FROM payment_invoices 
            WHERE user = %s 
            ORDER BY created_at DESC
        """, (user,))
        payments = cursor.fetchall()
        
        # Get student count
        cursor.execute("SELECT COUNT(*) as student_count FROM student_details")
        student_count = cursor.fetchone()['student_count']
        
        # Get information sheet count
        cursor.execute("SELECT COUNT(*) as info_count FROM student_information_sheet")
        info_count = cursor.fetchone()['info_count']
        
        # Calculate membership status
        now = datetime.now()
        status = "Unknown"
        if user_settings:
            expires = user_settings['updated_at']
            if user_settings['membership_plan'] == 'Trial':
                status = "Trial Expired" if now > expires else "Trial Active"
            else:
                status = "Expired" if now > expires else "Active"
        
        return render_template('admin/user_details.html',
                            db=db,
                            user=user,
                            user_settings=user_settings,
                            payments=payments,
                            student_count=student_count,
                            info_count=info_count,
                            status=status,
                            now=now)
        
    except Error as e:
        flash(f'Error fetching user details: {e}', 'danger')
        return redirect(url_for('admin_panel'))
    finally:
        cursor.close()
        user_conn.close()

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin', None)
    flash('Admin logged out successfully', 'success')
    return redirect(url_for('admin_login'))

@app.route('/photo')
def photo():
    now = datetime.now()
    timeString = now.strftime("%Y-%m-%d %H:%M")
    templateData = {
        'title': 'Latest Photo',
        'time': timeString
    }
    return render_template('photo1.html', **templateData)

@app.route('/test_session')
def test_session():
    user = session.get('user')
    return f"Session user: {user}, Full session: {session}"

@app.route('/user_dashboard/<db>')
def user_dashboard(db):
    user = session.get('user')
    if not user:
        flash('Please log in to access the dashboard', 'danger')
        return redirect(url_for('login'))

    DATABASES = get_databases()
    if db not in DATABASES:
        flash('Invalid database selected', 'danger')
        return redirect(url_for('login'))

    connection = connect_db(user, DATABASES[db]['password'], db)
    if connection:
        cursor = connection.cursor(dictionary=True)
        try:
            cursor.execute("""
                SELECT 
                    enroll_no,
                    name,
                    course,
                    total_fees,
                    balance_fees,
                    sex,
                    mobile_number1,
                    mobile_number2,
                    scheme
                FROM student_details
            """)
            students = cursor.fetchall()
        except Error as e:
            flash(f"Failed to fetch data: {e}", "danger")
            students = []
        finally:
            cursor.close()
            connection.close()
        
        logo_path = get_logo_path(db, user)
        
        return render_template(
            'application/user_dashboard.html',
            db=db,
            user=user,
            students=students,
            logo_path=logo_path
        )
    else:
        flash('Failed to connect to the database', 'danger')
        return redirect(url_for('login'))

@app.route('/application_form/<db>', methods=['GET', 'POST'])
def application_form(db):
    user = session.get('user')
    if not user:
        flash('Please log in to access this page', 'danger')
        return redirect(url_for('login'))

    DATABASES = get_databases()
    if db not in DATABASES:
        flash('Invalid database', 'danger')
        return redirect(url_for('login'))

    connection = connect_db(user, DATABASES[db]['password'], db)
    if not connection:
        flash('Failed to connect to database', 'error')
        return redirect(url_for('login'))

    cursor = connection.cursor(dictionary=True)
    logo_path = get_logo_path(db, user)

    if request.method == 'POST':
        try:
            enroll_no = request.form.get('enroll_no', '').strip().upper()
            if not enroll_no:
                enroll_no = f"ENR-{datetime.now().strftime('%Y%m%d%H%M%S')}"

            cursor.execute("SELECT COUNT(*) as count FROM student_details WHERE enroll_no = %s", (enroll_no,))
            if cursor.fetchone()['count'] > 0:
                flash(f'Enrollment number {enroll_no} already exists.', 'danger')
                return redirect(url_for('application_form', db=db))

            total_fees = float(request.form.get('total_fees', 0)) or 0
            net_fees = float(request.form.get('net_fees', 0)) or 0
            if net_fees > total_fees:
                flash('Net fees cannot exceed total fees', 'danger')
                return redirect(url_for('application_form', db=db))
            balance_fees = total_fees - net_fees

            bill_number = request.form.get('bill_number', '').strip().upper()
            if not bill_number:
                bill_number = f"BN-{enroll_no}-{datetime.now().strftime('%Y%m%d%H%M%S')}"

            mobile_number1 = request.form.get('mobile_number1', '').strip()
            if not mobile_number1 or not mobile_number1.isdigit() or len(mobile_number1) != 10:
                flash('Please provide a valid 10-digit Mobile Number 1', 'danger')
                return redirect(url_for('application_form', db=db))

            mobile_number2 = request.form.get('mobile_number2', '').strip()
            if mobile_number2 and (not mobile_number2.isdigit() or len(mobile_number2) != 10):
                flash('Mobile Number 2 must be a valid 10-digit number if provided', 'danger')
                return redirect(url_for('application_form', db=db))

            data = (
                enroll_no,
                request.form.get('course', '').upper(),
                request.form.get('sex', ''),
                request.form.get('name', '').upper(),
                request.form.get('father_name', '').upper() or None,
                mobile_number1,
                mobile_number2 or None,
                request.form.get('address1', '').upper() or None,
                request.form.get('address2', '').upper() or None,
                request.form.get('city', '').upper() or None,
                request.form.get('pincode', '').upper() or None,
                request.form.get('qualification', '').upper() or None,
                request.form.get('date_of_join') or None,
                request.form.get('age') or None,
                request.form.get('scheme', '').upper() or None,
                request.form.get('date_of_birth') or None,
                request.form.get('concession', '').upper() or None,
                net_fees,
                total_fees,
                net_fees,
                balance_fees
            )

            student_id = request.form.get('student_id')

            try:
                # Ensure no existing transaction is active
                if connection.in_transaction:
                    connection.rollback()  # Rollback any existing transaction
                connection.start_transaction()
                
                cursor.execute('''
                    INSERT INTO student_details (
                        enroll_no, course, sex, name, father_name, mobile_number1, mobile_number2,
                        address1, address2, city, pincode, qualification, date_of_join, age,
                        scheme, date_of_birth, concession, net_fees, total_fees, fees, balance_fees
                    ) 
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ''', data)

                if net_fees > 0:
                    cursor.execute("""
                        INSERT INTO fee_payments (enroll_no, fee_amount, bill_number, payment_date)
                        VALUES (%s, %s, %s, %s)
                    """, (enroll_no, net_fees, bill_number, datetime.now()))

                if student_id:
                    cursor.execute("""
                        UPDATE student_information_sheet 
                        SET status = %s, updated_at = %s 
                        WHERE id = %s
                    """, ('Joined', datetime.now(), student_id))

                connection.commit()
                flash('Student details added successfully', 'success')
                return redirect(url_for('user_dashboard', db=db))
            except Error as e:
                connection.rollback()
                flash(f'Error adding student: {e}', 'danger')
                return redirect(url_for('application_form', db=db))
        except Error as e:
            flash(f'Error processing form: {e}', 'danger')
            return redirect(url_for('application_form', db=db))
        finally:
            cursor.close()
            connection.close()

    # Fetch students from the database
    try:
        cursor.execute("SELECT * FROM student_details")
        students = cursor.fetchall()
    except Error as e:
        flash(f'Error fetching students: {e}', 'danger')
        students = []  # Fallback to empty list if query fails
    finally:
        cursor.close()
        connection.close()

    return render_template('application/add.html', db=db, students=students, logo_path=logo_path)

@app.route('/edit/<db>/<enroll_no>', methods=['GET', 'POST'])
def update_student(db, enroll_no):
    user = session.get('user')
    if not user:
        flash('Session expired. Please log in again.', 'warning')
        return redirect(url_for('login'))

    DATABASES = get_databases()
    if db not in DATABASES:
        flash('Invalid database code', 'danger')
        return redirect(url_for('login'))

    connection = connect_db(user, DATABASES[db]['password'], db)
    if not connection:
        flash('Failed to connect to the database', 'danger')
        return redirect(url_for('login'))

    cursor = connection.cursor(dictionary=True)
    if request.method == 'POST':
        try:
            cursor.execute("SELECT fees, total_fees FROM student_details WHERE enroll_no = %s", (enroll_no,))
            student = cursor.fetchone()
            if not student:
                flash('Student not found', 'danger')
                cursor.close()
                connection.close()
                return redirect(url_for('user_dashboard', db=db))

            total_fees = float(request.form['total_fees']) if request.form['total_fees'] else 0
            current_fees = float(student['fees'] or 0)
            new_balance_fees = total_fees - current_fees

            mobile_number1 = request.form.get('mobile_number1', '').strip()
            if not mobile_number1 or not mobile_number1.isdigit() or len(mobile_number1) != 10:
                flash('Please provide a valid 10-digit Mobile Number 1', 'danger')
                cursor.close()
                connection.close()
                return redirect(url_for('update_student', db=db, enroll_no=enroll_no))
                
            mobile_number2 = request.form.get('mobile_number2', '').strip()
            if mobile_number2 and (not mobile_number2.isdigit() or len(mobile_number2) != 10):
                flash('Mobile Number 2 must be a valid 10-digit number if provided', 'danger')
                cursor.close()
                connection.close()
                return redirect(url_for('update_student', db=db, enroll_no=enroll_no))

            if new_balance_fees < 0:
                flash('Total fees cannot be less than paid fees', 'danger')
                cursor.close()
                connection.close()
                return redirect(url_for('update_student', db=db, enroll_no=enroll_no))

            updated_data = (
                request.form['course'].upper(),
                request.form['sex'],
                request.form['name'].upper(),
                request.form['father_name'].upper() or None,
                mobile_number1,
                mobile_number2 or None,
                request.form['address1'].upper() or None,
                request.form.get('address2', '').upper(),
                request.form['city'].upper() or None,
                request.form['pincode'].upper() or None,
                request.form['qualification'].upper() or None,
                request.form['date_of_join'] or None,
                request.form['age'] or None,
                request.form['scheme'].upper() or None,
                request.form['date_of_birth'] or None,
                request.form.get('concession', '').upper(),
                total_fees,
                current_fees,
                new_balance_fees,
                datetime.now(),
                enroll_no
            )

            cursor.execute('''
                UPDATE student_details
                SET course=%s, sex=%s, name=%s, father_name=%s, mobile_number1=%s, mobile_number2=%s, 
                    address1=%s, address2=%s, city=%s, pincode=%s, 
                    qualification=%s, date_of_join=%s, age=%s, scheme=%s, 
                    date_of_birth=%s, concession=%s, total_fees=%s, fees=%s, 
                    balance_fees=%s, updated_at=%s
                WHERE enroll_no=%s
            ''', updated_data)
            connection.commit()
            flash('Student details updated successfully', 'success')
        except Error as e:
            connection.rollback()
            flash(f'Error updating student: {e}', 'danger')
        except ValueError as e:
            flash(f'Invalid input: {e}', 'danger')
        finally:
            cursor.close()
            connection.close()
        return redirect(url_for('user_dashboard', db=db))

    try:
        cursor.execute('''
            SELECT *, 
                DATE_FORMAT(date_of_join, '%Y-%m-%d') as date_of_join,
                DATE_FORMAT(date_of_birth, '%Y-%m-%d') as date_of_birth
            FROM student_details 
            WHERE enroll_no = %s
        ''', (enroll_no,))
        student = cursor.fetchone()
        if not student:
            flash('Student not found', 'danger')
            cursor.close()
            connection.close()
            return redirect(url_for('user_dashboard', db=db))

        logo_path = get_logo_path(db, user)
        return render_template('application/edit.html', db=db, student=student, logo_path=logo_path)
    except Error as e:
        flash(f'Error fetching student: {e}', 'danger')
        return redirect(url_for('user_dashboard', db=db))
    finally:
        cursor.close()
        connection.close()

@app.route('/delete/<db>', methods=['POST'])
def delete_student(db):
    user = session.get('user')
    if not user:
        return redirect(url_for('login'))

    DATABASES = get_databases()
    if db not in DATABASES:
        flash('Invalid database', 'danger')
        return redirect(url_for('login'))

    connection = connect_db(user, DATABASES[db]['password'], db)
    if connection:
        cursor = connection.cursor()
        try:
            enroll_no = request.form['enroll_no']
            connection.start_transaction()
            cursor.execute('DELETE FROM fee_payments WHERE enroll_no=%s', (enroll_no,))
            cursor.execute('DELETE FROM student_details WHERE enroll_no=%s', (enroll_no,))
            connection.commit()
            flash('Student record and payment history deleted successfully', 'success')
        except Error as e:
            connection.rollback()
            flash(f'Error deleting student: {e}', 'danger')
        finally:
            cursor.close()
            connection.close()
        return redirect(url_for('user_dashboard', db=db))
    else:
        flash('Failed to connect to the database', 'danger')
        return redirect(url_for('login'))
    
@app.route('/fees/<db>', methods=['GET', 'POST'])
def fees(db):
    user = session.get('user')
    if not user:
        flash('Session expired. Please log in again.', 'warning')
        return redirect(url_for('login'))
    
    DATABASES = get_databases()
    if db not in DATABASES:
        flash('Invalid database', 'danger')
        return redirect(url_for('login'))
    
    connection = connect_db(user, DATABASES[db]['password'], db)
    if not connection:
        flash('Failed to connect to the database', 'danger')
        return redirect(url_for('login'))
    
    try:
        cursor = connection.cursor(dictionary=True)
        
        if request.method == 'POST':
            enroll_no = request.form['enroll_no']
            bill_number = request.form['bill_number']
            try:
                fee_amount = float(request.form['fee_amount'])
                payment_date = datetime.now()
                
                if fee_amount <= 0:
                    flash('Fee amount must be positive', 'danger')
                    return redirect(url_for('fees', db=db, enroll_no=enroll_no))
                
                if not bill_number.strip():
                    flash('Bill number is required', 'danger')
                    return redirect(url_for('fees', db=db, enroll_no=enroll_no))
                
                connection.start_transaction()
                
                cursor.execute("""
                    SELECT total_fees, fees, balance_fees 
                    FROM student_details 
                    WHERE enroll_no = %(enroll_no)s
                    FOR UPDATE
                """, {'enroll_no': enroll_no})
                student = cursor.fetchone()
                
                if not student:
                    flash('Student not found', 'danger')
                    connection.rollback()
                    return redirect(url_for('fees', db=db))
                
                total_fees = float(student['total_fees'] or 0)
                current_fees = float(student['fees'] or 0)
                
                new_fees = current_fees + fee_amount
                new_balance = total_fees - new_fees
                
                if new_balance < 0:
                    flash('Payment exceeds remaining balance', 'danger')
                    connection.rollback()
                    return redirect(url_for('fees', db=db, enroll_no=enroll_no))
                
                cursor.execute("""
                    UPDATE student_details 
                    SET fees = %(fees)s, balance_fees = %(balance_fees)s, updated_at = %(updated_at)s
                    WHERE enroll_no = %(enroll_no)s
                """, {
                    'fees': new_fees,
                    'balance_fees': new_balance,
                    'updated_at': payment_date,
                    'enroll_no': enroll_no
                })
                
                cursor.execute("""
                    INSERT INTO fee_payments (enroll_no, fee_amount, bill_number, payment_date)
                    VALUES (%(enroll_no)s, %(fee_amount)s, %(bill_number)s, %(payment_date)s)
                """, {
                    'enroll_no': enroll_no,
                    'fee_amount': fee_amount,
                    'bill_number': bill_number,
                    'payment_date': payment_date
                })
                
                connection.commit()
                flash('Payment recorded successfully', 'success')
                
            except ValueError:
                flash('Invalid fee amount', 'danger')
                connection.rollback()
            except Error as e:
                connection.rollback()
                flash(f'Database error: {str(e)}', 'danger')
            
            return redirect(url_for('fees', db=db, enroll_no=enroll_no))
        
        enroll_no = request.args.get('enroll_no')
        student = None
        payment_history = []
        logo_path = get_logo_path(db, user)
        
        if enroll_no:
            cursor.execute("""
                SELECT 
                    id, enroll_no, name, course, father_name, 
                    total_fees, fees, balance_fees, scheme,
                    DATE_FORMAT(date_of_join, '%Y-%m-%d') as formatted_join_date,
                    DATE_FORMAT(date_of_birth, '%Y-%m-%d') as formatted_birth_date,
                    DATE_FORMAT(updated_at, '%Y-%m-%d %H:%i:%s') as last_updated
                FROM student_details 
                WHERE enroll_no = %(enroll_no)s
            """, {'enroll_no': enroll_no})
            student = cursor.fetchone()
            
            if student:
                cursor.execute("""
                    SELECT 
                        fee_amount, bill_number,
                        DATE_FORMAT(payment_date, '%Y-%m-%d %H:%i:%s') as payment_date
                    FROM fee_payments 
                    WHERE enroll_no = %(enroll_no)s
                    ORDER BY payment_date DESC
                """, {'enroll_no': enroll_no})
                payment_history = cursor.fetchall()
            else:
                flash('Student not found', 'warning')
        
        return render_template('data/fees.html', 
                            db=db, 
                            student=student, 
                            payment_history=payment_history,
                            logo_path=logo_path)
        
    except Error as e:
        flash(f'Database error: {str(e)}', 'danger')
        return redirect(url_for('user_dashboard', db=db))
    finally:
        if 'cursor' in locals():
            cursor.close()
        if connection:
            connection.close()

@app.route('/export_application/<db>/<table_name>', methods=['GET'])
def export_application(db, table_name):
    user = session.get('user')
    if not user:
        return redirect(url_for('login'))

    DATABASES = get_databases()
    if db not in DATABASES:
        flash('Invalid database', 'danger')
        return redirect(url_for('login'))

    connection = connect_db(user, DATABASES[db]['password'], db)
    if connection:
        cursor = connection.cursor(dictionary=True)
        try:
            course = request.args.get('course', '').strip()
            gender = request.args.get('gender', '').strip()

            query = """
                SELECT 
                    sd.name,
                    sis.father_name,
                    COALESCE(sis.mobile_number1, '') AS mobile_number1,
                    COALESCE(sis.mobile_number2, '') AS mobile_number2,
                    sd.course,
                    sd.created_at
                FROM student_details sd
                LEFT JOIN student_information_sheet sis 
                    ON LOWER(TRIM(sd.name)) = LOWER(TRIM(sis.name))
                WHERE 1=1
            """
            params = []

            if course:
                query += " AND sd.course = %s"
                params.append(course)
            if gender:
                query += " AND sd.sex = %s"
                params.append(gender)

            cursor.execute(query, params)
            rows = cursor.fetchall()

            if not rows:
                flash('No data available to export with the applied filters.', 'danger')
                return redirect(url_for('user_dashboard', db=db, course=course, gender=gender))

            fieldnames = ['Name', 'Father Name', 'Mobile Number 1', 'Mobile Number 2', 'Course', 'Created Date']

            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(fieldnames)

            for row in rows:
                created_date = row['created_at'].strftime('%Y-%m-%d') if row['created_at'] else ''
                writer.writerow([
                    row.get('name', ''),
                    row.get('father_name', ''),
                    row.get('mobile_number1', ''),
                    row.get('mobile_number2', ''),
                    row.get('course', ''),
                    created_date
                ])

            output.seek(0)

            filter_parts = []
            if course:
                filter_parts.append(f"course_{course}")
            if gender:
                filter_parts.append(f"gender_{gender}")
            filter_suffix = "_" + "_".join(filter_parts) if filter_parts else ""

            return send_file(
                io.BytesIO(output.getvalue().encode('utf-8')),
                mimetype='text/csv',
                as_attachment=True,
                download_name=f'{table_name}{filter_suffix}.csv'
            )

        except Error as e:
            flash(f"Failed to export data: {e}", "danger")
            return redirect(url_for('user_dashboard', db=db))
        finally:
            cursor.close()
            connection.close()
    else:
        flash('Failed to connect to the database', "danger")
        return redirect(url_for('login'))

@app.route('/export_information/<db>', methods=['GET'])
def export_information(db):
    user = session.get('user')
    if not user:
        return redirect(url_for('login'))

    DATABASES = get_databases()
    if db not in DATABASES:
        flash('Invalid database', 'danger')
        return redirect(url_for('login'))

    # Get filter parameters
    course_filter = request.args.get('course_filter', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')

    connection = connect_db(user, DATABASES[db]['password'], db)
    if connection:
        cursor = connection.cursor(dictionary=True)
        try:
            # Updated query to include mobile_number1 and mobile_number2
            query = """
                SELECT name, father_name, mobile_number1, mobile_number2, 
                    course_interested, created_at
                FROM student_information_sheet
                WHERE 1=1
            """
            params = []

            if course_filter:
                query += " AND course_interested = %s"
                params.append(course_filter)
            if date_from:
                query += " AND DATE(created_at) >= %s"
                params.append(date_from)
            if date_to:
                query += " AND DATE(created_at) <= %s"
                params.append(date_to)

            cursor.execute(query, params)
            rows = cursor.fetchall()

            if not rows:
                flash('No data available to export with the applied filters.', 'danger')
                return redirect(url_for('information_dashboard', db=db))

            # Create CSV in memory
            output = io.StringIO()
            writer = csv.writer(output)

            # Header
            writer.writerow([
                'Name', 'Father Name', 'Mobile Number 1', 'Mobile Number 2', 
                'Course Interested', 'Created Date'
            ])

            # Write data
            for row in rows:
                created_date = row['created_at'].strftime('%Y-%m-%d') if row['created_at'] else ''
                writer.writerow([
                    row['name'], row['father_name'],
                    row.get('mobile_number1', ''), row.get('mobile_number2', ''),
                    row['course_interested'], created_date
                ])

            # Filename formatting
            filename_parts = ['students']
            if course_filter:
                filename_parts.append(course_filter.replace(' ', '_'))
            if date_from or date_to:
                filename_parts.append(f"from_{date_from}_to_{date_to}")
            
            filename = '_'.join(filename_parts) + '.csv'

            output.seek(0)
            return Response(
                output.getvalue(),
                mimetype="text/csv",
                headers={"Content-Disposition": f"attachment;filename={filename}"}
            )

        except Error as e:
            flash(f"Failed to export data: {e}", "danger")
            app.logger.error(f"Export error: {str(e)}")
            return redirect(url_for('information_dashboard', db=db))
        finally:
            cursor.close()
            connection.close()
    else:
        flash('Failed to connect to the database', "danger")
        return redirect(url_for('login'))


@app.route('/report/<db>', methods=['GET', 'POST'])
def report(db):
    user = session.get('user')
    if not user:
        flash('Session expired. Please log in again.', 'warning')
        return redirect(url_for('login'))

    DATABASES = get_databases()
    if db not in DATABASES:
        flash('Invalid database', 'danger')
        return redirect(url_for('login'))

    connection = connect_db(user, DATABASES[db]['password'], db)
    if not connection:
        flash('Failed to connect to the database', 'danger')
        return redirect(url_for('login'))

    cursor = connection.cursor(dictionary=True)
    date_range_display = 'All Time'
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    try:
        course_performance = []
        courses = []
        fees = []
        student_counts = []
        total_revenue = 0
        monthly_data = {'months': [], 'total_fees': [], 'enrollments': []}
        course_enrollment_trends = {}

        query = '''
            SELECT 
                course,
                COUNT(*) as total_students,
                SUM(total_fees) as total_fees
            FROM student_details
            WHERE 1=1
        '''
        params = []

        if start_date and end_date:
            query += ' AND date_of_join BETWEEN %s AND %s'
            params.extend([start_date, end_date])
            date_range_display = f'from {start_date} to {end_date}'

        query += ' GROUP BY course'

        cursor.execute(query, params)
        course_performance = cursor.fetchall()

        total_revenue = sum(data['total_fees'] or 0 for data in course_performance)
        courses = [data['course'] or 'Unknown' for data in course_performance]
        student_counts = [data['total_students'] or 0 for data in course_performance]
        fees = [data['total_fees'] or 0 for data in course_performance]

        for data in course_performance:
            data['course'] = data['course'] or 'Unknown'
            data['total_students'] = data['total_students'] or 0
            data['total_fees'] = data['total_fees'] or 0

        total_students = sum(student_counts)
        active_courses = len(courses)
        avg_fee_per_student = total_revenue / total_students if total_students > 0 else 0

        monthly_query = '''
            SELECT 
                DATE_FORMAT(payment_date, '%Y-%m') as month,
                COALESCE(SUM(fee_amount), 0) as total_fees
            FROM fee_payments
            WHERE 1=1
        '''
        monthly_params = []

        if start_date and end_date:
            monthly_query += ' AND payment_date BETWEEN %s AND %s'
            monthly_params.extend([start_date, end_date])

        monthly_query += " GROUP BY DATE_FORMAT(payment_date, '%Y-%m') ORDER BY month"

        cursor.execute(monthly_query, monthly_params)
        monthly_fees = cursor.fetchall()

        enrollment_query = '''
            SELECT 
                DATE_FORMAT(date_of_join, '%Y-%m') as month,
                COUNT(*) as enrollments
            FROM student_details
            WHERE 1=1
        '''
        enrollment_params = []

        if start_date and end_date:
            enrollment_query += ' AND date_of_join BETWEEN %s AND %s'
            enrollment_params.extend([start_date, end_date])

        enrollment_query += " GROUP BY DATE_FORMAT(date_of_join, '%Y-%m') ORDER BY month"

        cursor.execute(enrollment_query, enrollment_params)
        monthly_enrollments = cursor.fetchall()

        all_months = set()
        fee_dict = {}
        enrollment_dict = {}

        for row in monthly_fees:
            month = row['month']
            all_months.add(month)
            fee_dict[month] = float(row['total_fees'] or 0)

        for row in monthly_enrollments:
            month = row['month']
            all_months.add(month)
            enrollment_dict[month] = int(row['enrollments'] or 0)

        all_months = sorted(all_months, key=lambda x: datetime.strptime(x, '%Y-%m'))
        
        monthly_data['months'] = [datetime.strptime(month, '%Y-%m').strftime('%b %Y') for month in all_months]
        monthly_data['total_fees'] = [fee_dict.get(month, 0) for month in all_months]
        monthly_data['enrollments'] = [enrollment_dict.get(month, 0) for month in all_months]

        top_courses = courses[:4]
        for course in top_courses:
            course_query = '''
                SELECT 
                    DATE_FORMAT(date_of_join, '%Y-%m') as month,
                    COUNT(*) as enrollments
                FROM student_details
                WHERE course = %s
            '''
            course_params = [course]
            
            if start_date and end_date:
                course_query += ' AND date_of_join BETWEEN %s AND %s'
                course_params.extend([start_date, end_date])
            
            course_query += " GROUP BY DATE_FORMAT(date_of_join, '%Y-%m') ORDER BY month"

            cursor.execute(course_query, course_params)
            course_data = cursor.fetchall()
            
            course_trend = [0] * len(all_months)
            
            for row in course_data:
                month = row['month']
                if month in all_months:
                    index = all_months.index(month)
                    course_trend[index] = int(row['enrollments'] or 0)
            
            course_enrollment_trends[course] = {
                'months': monthly_data['months'],
                'enrollments': course_trend
            }

    except Error as e:
        flash(f'Error fetching report data: {e}', 'danger')
        course_performance = []
        courses = []
        fees = []
        student_counts = []
        total_revenue = 0
        total_students = 0
        active_courses = 0
        avg_fee_per_student = 0
        monthly_data = {'months': [], 'total_fees': [], 'enrollments': []}
        course_enrollment_trends = {}
    finally:
        cursor.close()
        connection.close()

    logo_path = get_logo_path(db, user)

    return render_template(
        'report/report_course.html',
        db=db,
        course_performance=course_performance,
        courses=courses,
        fees=fees,
        student_counts=student_counts,
        total_revenue=total_revenue,
        total_students=total_students,
        active_courses=active_courses,
        avg_fee_per_student=avg_fee_per_student,
        monthly_data=monthly_data,
        course_enrollment_trends=course_enrollment_trends,
        date_range_display=date_range_display,
        logo_path=logo_path,
        start_date=start_date,
        end_date=end_date
    )

@app.route('/export_report/<db>', methods=['GET'])
def export_report(db):
    user = session.get('user')
    if not user:
        flash('Session expired. Please log in again.', 'warning')
        return redirect(url_for('login'))

    DATABASES = get_databases()
    if db not in DATABASES:
        flash('Invalid database', 'danger')
        return redirect(url_for('login'))

    connection = connect_db(user, DATABASES[db]['password'], db)
    if not connection:
        flash('Failed to connect to the database', 'danger')
        return redirect(url_for('login'))

    cursor = connection.cursor(dictionary=True)
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    try:
        query = '''
            SELECT 
                course,
                COUNT(*) AS total_students,
                COALESCE(SUM(total_fees), 0) AS total_fees
            FROM student_details
            WHERE 1=1
        '''
        params = []

        if start_date and end_date:
            query += ' AND date_of_join BETWEEN %s AND %s'
            params.extend([start_date, end_date])

        query += ' GROUP BY course'

        cursor.execute(query, params)
        course_performance = cursor.fetchall()

        total_revenue = sum(data['total_fees'] or 0 for data in course_performance)

        export_data = []
        for data in course_performance:
            percentage = ((data['total_fees'] / total_revenue) * 100) if total_revenue > 0 else 0.0
            export_data.append({
                'Course': data['course'] or 'Unknown',
                'Total Students': data['total_students'] or 0,
                'Total Fees (₹)': data['total_fees'] or 0,
                'Percentage of Total Revenue (%)': round(percentage, 1)
            })

        df = pd.DataFrame(export_data)

        output = BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='Course Performance')
        output.seek(0)

        date_suffix = f"{start_date}_{end_date}" if start_date and end_date else "all_time"
        filename = f"course_report_{date_suffix}.xlsx"

        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            download_name=filename,
            as_attachment=True
        )

    except Error as e:
        flash(f'Error exporting data: {e}', 'danger')
        return redirect(url_for('report', db=db))
    except Exception as e:
        flash(f'Error generating Excel file: {e}', 'danger')
        return redirect(url_for('report', db=db))
    finally:
        cursor.close()
        connection.close()

@app.route('/weekly_report/<db>', methods=['GET'])
def weekly_report(db):
    user = session.get('user')
    if not user:
        return redirect(url_for('login'))

    DATABASES = get_databases()
    if db not in DATABASES:
        flash('Invalid database', 'danger')
        return redirect(url_for('login'))

    period = request.args.get('period', 'week')
    selected_month = request.args.get('month', '')
    connection = connect_db(user, DATABASES[db]['password'], db)
    if connection:
        cursor = connection.cursor(dictionary=True)
        try:
            cursor.execute("""
                SELECT DISTINCT DATE_FORMAT(payment_date, '%Y-%m') as month
                FROM fee_payments
                UNION
                SELECT DISTINCT DATE_FORMAT(date_of_join, '%Y-%m') as month
                FROM student_details
                ORDER BY month DESC
            """)
            available_months = [row['month'] for row in cursor.fetchall()]

            if period == 'not_joined':
                cursor.execute("""
                    SELECT id, name, course_interested, mobile_number1, mobile_number2, status
                    FROM student_information_sheet
                    WHERE status != 'Joined' OR status IS NULL
                    ORDER BY created_at DESC
                """)
                not_joined_students = cursor.fetchall()
                logo_path = get_logo_path(db, user)
                return render_template('report/weekly_report.html',
                                db=db,
                                period=period,
                                not_joined_students=not_joined_students,
                                available_months=available_months,
                                logo_path=logo_path
                                )
            
            today = date.today()
            date_range_display = ""
            start_date = None
            end_date = None

            if period == 'previous_month' and selected_month:
                try:
                    year, month = map(int, selected_month.split('-'))
                    start_date = date(year, month, 1)
                    next_month = start_date.replace(day=28) + timedelta(days=4)
                    end_date = next_month - timedelta(days=next_month.day)
                    date_range_display = f"{start_date.strftime('%B %Y')}"
                except ValueError:
                    flash('Invalid month format', 'danger')
                    return redirect(url_for('weekly_report', db=db, period='week'))
            elif period == 'day':
                start_date = today
                end_date = today
                date_range_display = today.strftime('%d %b %Y')
            elif period == 'week':
                start_date = today - timedelta(days=today.weekday())
                end_date = start_date + timedelta(days=6)
                date_range_display = f"{start_date.strftime('%d %b %Y')} to {end_date.strftime('%d %b %Y')}"
            else:
                start_date = today.replace(day=1)
                next_month = today.replace(day=28) + timedelta(days=4)
                end_date = next_month - timedelta(days=next_month.day)
                date_range_display = f"{start_date.strftime('%d %b %Y')} to {end_date.strftime('%d %b %Y')}"

            cursor.execute("""
                SELECT 
                    sd.course,
                    COUNT(DISTINCT sd.enroll_no) as total_students,
                    COALESCE(SUM(fp.fee_amount), 0) as total_fees
                FROM student_details sd
                LEFT JOIN fee_payments fp ON sd.enroll_no = fp.enroll_no 
                    AND fp.payment_date BETWEEN %s AND %s
                GROUP BY sd.course
            """, (start_date, end_date))
            report_data = {
                row['course']: {
                    'total_students': row['total_students'],
                    'total_fees': float(row['total_fees'] or 0)
                } for row in cursor.fetchall()
            }

            total_students = sum(data['total_students'] for data in report_data.values())
            total_fees = sum(data['total_fees'] for data in report_data.values())

            max_fee_course = max(report_data.items(), key=lambda x: x[1]['total_fees'], default=('None', {'total_fees': 0}))
            max_fee_course_name = max_fee_course[0]
            max_fee_amount = max_fee_course[1]['total_fees']

            max_student_course = max(report_data.items(), key=lambda x: x[1]['total_students'], default=('None', {'total_students': 0}))
            max_student_course_name = max_student_course[0]
            max_student_count = max_student_course[1]['total_students']

            logo_path = get_logo_path(db, user)
            return render_template('report/weekly_report.html', 
                            db=db,
                            period=period,
                            selected_month=selected_month,
                            report_data=report_data,
                            total_students=total_students,
                            total_fees=total_fees,
                            max_fee_course=max_fee_course_name,
                            max_fee_amount=max_fee_amount,
                            max_student_course=max_student_course_name,
                            max_student_count=max_student_course,
                            date_range_display=date_range_display,
                            available_months=available_months,
                            logo_path=logo_path)
        
        except Error as e:
            flash(f"Failed to fetch weekly report data: {e}", 'danger')
            return redirect(url_for('user_dashboard', db=db))
        
        finally:
            cursor.close()
            connection.close()
    else:
        flash('Failed to connect to the database', 'danger')
        return redirect(url_for('login'))

@app.route('/information_dashboard/<db>', methods=['GET'])
def information_dashboard(db):
    user = session.get('user')
    if not user:
        return redirect(url_for('login'))

    DATABASES = get_databases()
    app.logger.info(f"Connecting to database: {db}, Available databases: {DATABASES}")
    if db not in DATABASES:
        flash('Invalid database', 'danger')
        return redirect(url_for('login'))

    course_filter = request.args.get('course_interested', '')
    status_filter = request.args.get('status', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')

    connection = connect_db(user, DATABASES[db]['password'], db)
    if not connection:
        flash("Failed to connect to the database", "danger")
        return redirect(url_for('login'))

    cursor = connection.cursor(dictionary=True)
    try:
        # Verify schema
        cursor.execute("SHOW COLUMNS FROM student_information_sheet LIKE 'scheme'")
        if not cursor.fetchone():
            flash("Database schema is outdated. Missing 'scheme' column.", "danger")
            app.logger.error("Missing 'scheme' column in student_information_sheet")
            return redirect(url_for('login'))

        query = "SELECT * FROM student_information_sheet WHERE 1=1"
        params = []

        if course_filter:
            query += " AND course_interested = %s"
            params.append(course_filter)
        if status_filter:
            query += " AND status = %s"
            params.append(status_filter)
        if date_from:
            query += " AND DATE(created_at) >= %s"
            params.append(date_from)
        if date_to:
            query += " AND DATE(created_at) <= %s"
            params.append(date_to)

        query += " ORDER BY created_at DESC"
        app.logger.info(f"Executing query: {query} with params: {params}")

        cursor.execute(query, params)
        students = cursor.fetchall()

        cursor.execute("SELECT DISTINCT course_interested FROM student_information_sheet")
        courses = [course['course_interested'] for course in cursor.fetchall()]
        cursor.execute("SELECT DISTINCT scheme FROM student_information_sheet")
        schemes = [scheme['scheme'] for scheme in cursor.fetchall()]

        logo_path = get_logo_path(db, user)

        return render_template('information/user_dashboard.html', 
                            students=students, 
                            db=db, 
                            logo_path=logo_path,
                            courses=courses,
                            schemes=schemes,
                            current_filters={
                                'course_interested': course_filter,
                                'status': status_filter,
                                'date_from': date_from,
                                'date_to': date_to
                            })
    except Error as e:
        flash(f"Failed to fetch data: {e}", "danger")
        app.logger.error(f"Database error: {str(e)}")
    finally:
        cursor.close()
        connection.close()
    return redirect(url_for('login'))

@app.route('/information_form/<db>', methods=['GET', 'POST'])
def information_form(db):
    user = session.get('user')
    if not user:
        flash('Please log in to accessinį')
        return redirect(url_for('login'))

    DATABASES = get_databases()
    app.logger.info(f"Connecting to database: {db}, Available databases: {DATABASES}")
    if db not in DATABASES:
        flash('Invalid database', 'danger')
        return redirect(url_for('login'))

    connection = connect_db(user, DATABASES[db]['password'], db)
    if not connection:
        flash('Failed to connect to database', 'danger')
        return redirect(url_for('login'))

    cursor = connection.cursor(dictionary=True)
    
    if request.method == 'POST':
        try:
            # Generate a unique identifier using timestamp (if needed for display)
            sno = f"SNO-{datetime.now().strftime('%Y%m%d%H%M%S')}"
            mobile_number1 = request.form.get('mobile_number1', '').strip()
            if not mobile_number1 or not mobile_number1.isdigit() or len(mobile_number1) != 10:
                flash('Please provide a valid 10-digit Mobile Number 1', 'danger')
                cursor.close()
                connection.close()
                return redirect(url_for('information_form', db=db))

            mobile_number2 = request.form.get('mobile_number2', '').strip()
            if mobile_number2 and (not mobile_number2.isdigit() or len(mobile_number2) != 10):
                flash('Mobile Number 2 must be a valid 10-digit number if provided', 'danger')
                cursor.close()
                connection.close()
                return redirect(url_for('information_form', db=db))

            # Updated form_data without sno if it doesn't exist in database
            form_data = (
                request.form.get('name', '').strip() or None,
                request.form.get('father_name', '').strip() or 'NONE',
                mobile_number1,
                mobile_number2 or 'NONE',
                request.form.get('employment_status', '').strip() or 'NONE',
                request.form.get('address', '').strip() or 'NONE',
                request.form.get('pin_code', '').strip() or 'NONE',
                request.form.get('sex', '').strip() or 'NONE',
                request.form.get('qualification', '').strip() or 'NONE',
                request.form.get('reason', '').strip() or 'NONE',
                request.form.get('course_interested', '').strip() or None,
                request.form.get('joining_plan', '').strip() or 'NONE',
                request.form.get('source_info', '').strip() or 'NONE',
                request.form.get('scheme', '').strip() or 'NONE',
                'Pending',
                datetime.now()
            )

            required_fields = ['name', 'mobile_number1', 'course_interested']
            for field in required_fields:
                if not request.form.get(field):
                    flash(f"{field.replace('_', ' ').title()} is required", 'danger')
                    cursor.close()
                    connection.close()
                    return redirect(url_for('information_form', db=db))

            try:
                connection.start_transaction()
                # Updated insert query without sno column
                insert_query = """
                    INSERT INTO student_information_sheet 
                    (name, father_name, mobile_number1, mobile_number2, employment_status, 
                    address, pin_code, sex, qualification, reason, course_interested, 
                    joining_plan, source_info, scheme, status, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """
                cursor.execute(insert_query, form_data)
                connection.commit()
                flash('Student information added successfully', 'success')
                return redirect(url_for('information_dashboard', db=db))
            except Error as e:
                connection.rollback()
                flash(f'Error adding student information: {e}', 'danger')
                app.logger.error(f'Database error: {e}')
            finally:
                cursor.close()
                connection.close()
        except Exception as e:
            flash(f'An error occurred: {e}', 'danger')
            app.logger.error(f'Form submission error: {e}')
            cursor.close()
            connection.close()
            return redirect(url_for('information_form', db=db))

    try:
        # Verify schema
        cursor.execute("SHOW COLUMNS FROM student_information_sheet LIKE 'scheme'")
        if not cursor.fetchone():
            flash("Database schema is outdated. Missing 'scheme' column.", "danger")
            app.logger.error("Missing 'scheme' column in student_information_sheet")
            cursor.close()
            connection.close()
            return redirect(url_for('login'))

        cursor.execute("SELECT DISTINCT course_interested FROM student_information_sheet")
        courses = [course['course_interested'] for course in cursor.fetchall()]
        cursor.execute("SELECT DISTINCT scheme FROM student_information_sheet")
        schemes = [scheme['scheme'] for scheme in cursor.fetchall()]
        
        # Fixed query: removed 'sno' column reference
        cursor.execute("SELECT name, course_interested, sex, mobile_number1, mobile_number2 FROM student_information_sheet")
        students = cursor.fetchall()
        
        logo_path = get_logo_path(db, user)
        return render_template('information/add.html',
                            db=db,
                            logo_path=logo_path,
                            courses=courses,
                            schemes=schemes,
                            students=students)
    
    except Error as e:
        flash(f'Error fetching data: {e}', 'danger')
        app.logger.error(f'Database query error: {e}')
        cursor.close()
        connection.close()
        return redirect(url_for('information_dashboard', db=db))
    
    finally:
        cursor.close()
        connection.close()

@app.route('/join/<db>/<student_id>', methods=['POST'])
def join_student(db, student_id):
    user = session.get('user')
    if not user:
        flash('Session expired. Please log in again.', 'warning')
        return redirect(url_for('login'))

    DATABASES = get_databases()
    if db not in DATABASES:
        flash('Invalid database', 'danger')
        return redirect(url_for('login'))

    connection = connect_db(user, DATABASES[db]['password'], db)
    if not connection:
        flash('Failed to connect to the database', 'danger')
        return redirect(url_for('login'))

    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("""
            SELECT * FROM student_information_sheet 
            WHERE id = %s
        """, (student_id,))
        student = cursor.fetchone()

        if not student:
            flash('Student not found', 'danger')
            return redirect(url_for('information_dashboard', db=db))

        student_status = student.get('status', 'Pending')
        if student_status == 'Joined':
            flash('Student has already joined', 'warning')
            return redirect(url_for('information_dashboard', db=db))

        enroll_no = f"ENR-{uuid.uuid4().hex[:8]}"
        student_data = {
            'enroll_no': enroll_no,
            'name': student['name'],
            'father_name': student.get('father_name', ''),
            'course': student['course_interested'],
            'sex': student.get('sex', 'Male'),
            'address1': student.get('address', ''),
            'pincode': student.get('pin_code', ''),
            'qualification': student.get('qualification', ''),
            'date_of_join': date.today().strftime('%Y-%m-%d'),
            'address2': '',
            'city': '',
            'date_of_birth': '',
            'age': '',
            'scheme': '',
            'concession': '',
            'total_fees': '',
            'net_fees': '',
            'bill_number': ''
        }

        return render_template('application/add.html', db=db, student=student_data, student_id=student_id)

    except Error as e:
        flash(f'Database error: {str(e)}', 'danger')
        return redirect(url_for('information_dashboard', db=db))
    finally:
        cursor.close()
        connection.close()

@app.route('/update_status/<db>/<int:student_id>', methods=['POST'])
def update_status(db, student_id):
    user = session.get('user')
    if not user:
        return redirect(url_for('login'))

    DATABASES = get_databases()
    if db not in DATABASES:
        flash('Invalid database', 'danger')
        return redirect(url_for('login'))

    connection = connect_db(user, DATABASES[db]['password'], db)
    if not connection:
        flash('Failed to connect to the database', 'danger')
        return redirect(url_for('login'))

    cursor = connection.cursor(dictionary=True)
    try:
        status = request.form.get('status')
        if not status:
            flash('Status is required', 'danger')
            return redirect(url_for('information_dashboard', db=db))

        cursor.execute("""
            UPDATE student_information_sheet 
            SET status = %s, updated_at = %s 
            WHERE id = %s
        """, (status, datetime.now(), student_id))
        connection.commit()
        flash('Status updated successfully', 'success')
    except Error as e:
        connection.rollback()
        flash(f'Error updating status: {e}', 'danger')
    finally:
        cursor.close()
        connection.close()
    
    return redirect(url_for('information_dashboard', db=db))

@app.route('/edit_information/<db>/<int:student_id>', methods=['GET', 'POST'])
def edit_information(db, student_id):
    user = session.get('user')
    if not user:
        flash('Session expired. Please log in again.', 'warning')
        return redirect(url_for('login'))

    DATABASES = get_databases()
    if db not in DATABASES:
        flash('Invalid database', 'danger')
        return redirect(url_for('login'))

    connection = connect_db(user, DATABASES[db]['password'], db)
    if not connection:
        flash('Failed to connect to the database', 'danger')
        return redirect(url_for('login'))

    cursor = connection.cursor(dictionary=True)
    logo_path = get_logo_path(db, user)

    if request.method == 'POST':
        try:
            mobile_number1 = request.form.get('mobile_number1', '').strip()
            if not mobile_number1 or not mobile_number1.isdigit() or len(mobile_number1) != 10:
                flash('Please provide a valid 10-digit Mobile Number 1', 'danger')
                return redirect(url_for('edit_information', db=db, student_id=student_id))

            mobile_number2 = request.form.get('mobile_number2', '').strip()
            if mobile_number2 and (not mobile_number2.isdigit() or len(mobile_number2) != 10):
                flash('Mobile Number 2 must be a valid 10-digit number if provided', 'danger')
                return redirect(url_for('edit_information', db=db, student_id=student_id))

            updated_data = (
                request.form.get('name', '').strip() or None,
                request.form.get('father_name', '').strip() or 'NONE',
                mobile_number1,
                mobile_number2 or 'NONE',
                request.form.get('employment_status', '').strip() or 'NONE',
                request.form.get('address', '').strip() or 'NONE',
                request.form.get('pin_code', '').strip() or 'NONE',
                request.form.get('sex', '').strip() or 'NONE',
                request.form.get('qualification', '').strip() or 'NONE',
                request.form.get('reason', '').strip() or 'NONE',
                request.form.get('course_interested', '').strip() or None,
                request.form.get('joining_plan', '').strip() or 'NONE',
                request.form.get('source_info', '').strip() or 'NONE',
                request.form.get('scheme', '').strip() or 'NONE',
                datetime.now(),
                student_id
            )

            required_fields = ['name', 'mobile_number1', 'course_interested']
            for field in required_fields:
                if not request.form.get(field):
                    flash(f"{field.replace('_', ' ').title()} is required", 'danger')
                    return redirect(url_for('edit_information', db=db, student_id=student_id))

            cursor.execute("""
                UPDATE student_information_sheet
                SET name = %s, father_name = %s, mobile_number1 = %s, mobile_number2 = %s,
                    employment_status = %s, address = %s, pin_code = %s, sex = %s,
                    qualification = %s, reason = %s, course_interested = %s,
                    joining_plan = %s, source_info = %s, scheme = %s, updated_at = %s
                WHERE id = %s
            """, updated_data)
            connection.commit()
            flash('Student information updated successfully', 'success')
            return redirect(url_for('information_dashboard', db=db))
        except Error as e:
            connection.rollback()
            flash(f'Error updating student information: {e}', 'danger')
            return redirect(url_for('edit_information', db=db, student_id=student_id))
        finally:
            cursor.close()
            connection.close()

    try:
        cursor.execute("SELECT * FROM student_information_sheet WHERE id = %s", (student_id,))
        student = cursor.fetchone()
        if not student:
            flash('Student not found', 'danger')
            cursor.close()
            connection.close()
            return redirect(url_for('information_dashboard', db=db))

        cursor.execute("SELECT DISTINCT course_interested FROM student_information_sheet")
        courses = [course['course_interested'] for course in cursor.fetchall()]
        cursor.execute("SELECT DISTINCT scheme FROM student_information_sheet")
        schemes = [scheme['scheme'] for scheme in cursor.fetchall()]

        return render_template('information/edit.html',
                            db=db,
                            student=student,
                            logo_path=logo_path,
                            courses=courses,
                            schemes=schemes)
    except Error as e:
        flash(f'Error fetching student information: {e}', 'danger')
        return redirect(url_for('information_dashboard', db=db))
    finally:
        cursor.close()
        connection.close()

@app.route('/delete_information/<db>/<int:student_id>', methods=['POST'])
def delete_information(db, student_id):
    user = session.get('user')
    if not user:
        flash('Session expired. Please log in again.', 'warning')
        return redirect(url_for('login'))

    DATABASES = get_databases()
    if db not in DATABASES:
        flash('Invalid database', 'danger')
        return redirect(url_for('login'))

    connection = connect_db(user, DATABASES[db]['password'], db)
    if not connection:
        flash('Failed to connect to the database', 'danger')
        return redirect(url_for('login'))

    cursor = connection.cursor()
    try:
        cursor.execute("DELETE FROM student_information_sheet WHERE id = %s", (student_id,))
        connection.commit()
        flash('Student information deleted successfully', 'success')
    except Error as e:
        connection.rollback()
        flash(f'Error deleting student information: {e}', 'danger')
    finally:
        cursor.close()
        connection.close()

    return redirect(url_for('information_dashboard', db=db))

@app.route('/settings/<db>', methods=['GET', 'POST'])
def user_settings(db):
    user = session.get('user')
    if not user:
        flash('Session expired. Please log in again.', 'warning')
        return redirect(url_for('login'))

    DATABASES = get_databases()
    if db not in DATABASES:
        flash('Invalid database', 'danger')
        return redirect(url_for('login'))

    connection = connect_db(user, DATABASES[db]['password'], db)
    if not connection:
        flash('Failed to connect to the database', 'danger')
        return redirect(url_for('login'))

    cursor = connection.cursor(dictionary=True)
    logo_path = get_logo_path(db, user)
    now = datetime.now()

    if request.method == 'POST':
        try:
            membership_plan = request.form.get('membership_plan')
            membership_payment = float(request.form.get('membership_payment', '0.00'))

            if membership_payment < 0:
                flash('Membership payment amount cannot be negative', 'danger')
                return redirect(url_for('user_settings', db=db))

            cursor.execute("""
                INSERT INTO user_settings (user, membership_plan, membership_payment, logo_path, updated_at)
                VALUES (%s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    membership_plan = %s,
                    membership_payment = %s,
                    updated_at = %s
            """, (
                user, membership_plan, membership_payment, logo_path or 'image/logo.png', now,
                membership_plan, membership_payment, now
            ))
            connection.commit()
            flash('Settings updated successfully', 'success')
            return redirect(url_for('user_dashboard', db=db))

        except ValueError:
            flash('Invalid payment amount', 'danger')
            return redirect(url_for('user_settings', db=db))
        except Error as e:
            connection.rollback()
            flash(f'Error updating settings: {str(e)}', 'danger')
            return redirect(url_for('user_settings', db=db))
        finally:
            cursor.close()
            connection.close()
            return

    try:
        cursor.execute("SELECT * FROM user_settings WHERE user = %s", (user,))
        settings = cursor.fetchone()
        return render_template(
            'settings.html',
            db=db,
            user=user,
            settings=settings,
            logo_path=logo_path
        )
    except Error as e:
        flash(f'Error fetching settings: {e}', 'danger')
        return redirect(url_for('user_dashboard', db=db))
    finally:
        cursor.close()
        connection.close()


@app.route('/error_logs')
def view_error_logs():
    if 'admin' not in session:
        flash('Please login as admin', 'warning')
        return redirect(url_for('admin_login'))
    
    try:
        with open('app.log', 'r') as log_file:
            logs = log_file.readlines()
        return render_template('admin/error_logs.html', logs=logs)
    except FileNotFoundError:
        flash('Log file not found', 'danger')
        return redirect(url_for('admin_panel'))
    except Exception as e:
        flash(f'Error reading log file: {e}', 'danger')
        return redirect(url_for('admin_panel'))
    
@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('trial_expired', None)
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    initialize_databases()
    app.run(host='0.0.0.0', port=5000, debug=True)