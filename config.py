from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from datetime import datetime
import os

# ===== Konfigurasi Aplikasi =====
class Config:
    SECRET_KEY = 'supersecretkey123'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///site.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = 'static/uploads'
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'your_email@gmail.com'  # ganti email kamu
    MAIL_PASSWORD = 'your_app_password'     # ganti app password Gmail

# ===== Inisialisasi Aplikasi =====
app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = "info"

mail = Mail(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Pastikan folder upload ada
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# ===== Constants =====
PAYMENT_METHODS = ['BCA', 'Dana', 'ShopeePay', 'QRIS']
SHIPPING_METHODS = ['JNE', 'SiCepat', 'GoSend', 'GrabExpress', 'POS Indonesia']

# ===== Models =====
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), default='user')
    alamat = db.Column(db.String(250))
    rt = db.Column(db.String(10))
    rw = db.Column(db.String(10))
    kecamatan = db.Column(db.String(100))
    kelurahan = db.Column(db.String(100))
    provinsi = db.Column(db.String(100))
    is_verified = db.Column(db.Boolean, default=False)
    transactions = db.relationship('Transaction', backref='user', lazy=True)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Float, nullable=False)
    image = db.Column(db.String(150))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    transactions = db.relationship('Transaction', backref='product', lazy=True)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, default=1)
    total_price = db.Column(db.Float)
    payment_method = db.Column(db.String(50))
    shipping_method = db.Column(db.String(50))
    payment_proof = db.Column(db.String(150))
    status = db.Column(db.String(50), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class AdminLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150))
    email = db.Column(db.String(150))
    provinsi = db.Column(db.String(100))
    date_joined = db.Column(db.DateTime, default=datetime.utcnow)

# ===== Login Manager =====
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ===== Helper =====
def get_cart():
    if 'cart' not in session:
        session['cart'] = {}
    return session['cart']

def save_cart(cart):
    session['cart'] = cart
    session.modified = True

# ===== Routes =====
@app.route('/')
@login_required
def index():
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    products = Product.query.all()
    return render_template('user_dashboard.html', user=current_user, products=products)

# ===== Register/Login =====
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.form
        email = data['email'].lower()
        existing_user = User.query.filter_by(email=email).first()

        if existing_user and existing_user.is_verified:
            flash("Email sudah terdaftar dan diverifikasi! Gunakan email lain.", "danger")
            return redirect(url_for('register'))

        requested_role = data.get('role', 'user')
        admin_count = User.query.filter_by(role='admin').count()
        role = 'admin' if requested_role=='admin' and admin_count < 4 else 'user'

        hashed_password = generate_password_hash(data['password'], method='scrypt')

        if existing_user and not existing_user.is_verified:
            db.session.delete(existing_user)
            db.session.commit()
            flash("Email belum diverifikasi sebelumnya. Data lama dihapus, silakan cek email baru.", "info")

        user = User(
            name=data['name'],
            email=email,
            password=hashed_password,
            role=role,
            alamat=data.get('alamat'),
            rt=data.get('rt'),
            rw=data.get('rw'),
            kecamatan=data.get('kecamatan'),
            kelurahan=data.get('kelurahan'),
            provinsi=data.get('provinsi'),
            is_verified=False
        )
        db.session.add(user)
        db.session.commit()

        if role == 'admin':
            admin_log = AdminLog(name=user.name, email=user.email, provinsi=user.provinsi)
            db.session.add(admin_log)
            db.session.commit()

        # Kirim email verifikasi
        try:
            token = s.dumps(user.email, salt='email-confirm')
            verify_url = url_for('verify_email', token=token, _external=True)
            msg = Message('Verifikasi Email Anda', sender=app.config['MAIL_USERNAME'], recipients=[user.email])
            msg.body = f'Klik link ini untuk verifikasi email: {verify_url}'
            mail.send(msg)
            flash(f'Registrasi berhasil! Role: {role}. Email verifikasi telah dikirim ke {user.email}.', 'success')
        except:
            flash(f'Registrasi berhasil! Role: {role}. Email verifikasi gagal dikirim, silakan login. (Error di-skip)', 'warning')

        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].lower()
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            if not user.is_verified:
                flash('Email belum diverifikasi, tapi login diizinkan untuk testing.', 'warning')
            login_user(user)
            flash("Login berhasil!", "success")
            return redirect(url_for('admin_dashboard') if user.role=='admin' else url_for('index'))
        flash('Email atau password salah!', 'danger')
    return render_template('login.html')

@app.route('/verify_email/<token>')
def verify_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
        user = User.query.filter_by(email=email).first_or_404()
        if user.is_verified:
            flash('Email sudah diverifikasi.', 'info')
        else:
            user.is_verified = True
            db.session.commit()
            flash('Email berhasil diverifikasi!', 'success')
    except:
        flash('Token verifikasi tidak valid atau sudah kadaluarsa.', 'danger')
    return redirect(url_for('login'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Berhasil logout.", "info")
    return redirect(url_for('login'))

# ===== Admin Routes =====
@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Akses ditolak!', 'danger')
        return redirect(url_for('index'))
    products = Product.query.all()
    transactions = Transaction.query.all()
    return render_template('admin_dashboard.html', user=current_user, products=products, transactions=transactions)

@app.route('/admin/add_product', methods=['GET', 'POST'])
@login_required
def add_product():
    if current_user.role != 'admin':
        flash('Akses ditolak!', 'danger')
        return redirect(url_for('index'))
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        price = float(request.form['price'])
        image_file = request.files.get('image')
        filename = None
        if image_file and image_file.filename != '':
            filename = secure_filename(image_file.filename)
            image_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        product = Product(name=name, description=description, price=price, image=filename)
        db.session.add(product)
        db.session.commit()
        flash('Produk berhasil ditambahkan!', 'success')
        return redirect(url_for('add_product'))
    products = Product.query.all()
    return render_template('add_product.html', products=products)

@app.route('/product/<int:product_id>')
@login_required
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    return render_template('product_detail.html', product=product)

# ===== Cart & Checkout =====
@app.route('/add_to_cart/<int:product_id>')
@login_required
def add_to_cart(product_id):
    cart = get_cart()
    cart[str(product_id)] = cart.get(str(product_id), 0) + 1
    save_cart(cart)
    flash('Produk ditambahkan ke keranjang!', 'success')
    return redirect(url_for('index'))

@app.route('/cart')
@login_required
def view_cart():
    cart = get_cart()
    products = []
    total = 0
    for pid, qty in cart.items():
        product = Product.query.get(int(pid))
        if product:
            subtotal = product.price * qty
            products.append({'product': product, 'qty': qty, 'subtotal': subtotal})
            total += subtotal
    return render_template('cart.html', products=products, total=total)

@app.route('/remove_from_cart/<int:product_id>')
@login_required
def remove_from_cart(product_id):
    cart = get_cart()
    cart.pop(str(product_id), None)
    save_cart(cart)
    flash('Produk dihapus dari keranjang!', 'info')
    return redirect(url_for('view_cart'))

@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    cart = get_cart()
    if not cart:
        flash("Keranjang kosong!", "warning")
        return redirect(url_for('index'))
    if request.method == 'POST':
        payment_method = request.form['payment_method']
        shipping_method = request.form['shipping_method']

        if payment_method not in PAYMENT_METHODS:
            flash('Metode pembayaran tidak valid!', 'danger')
            return redirect(url_for('checkout'))

        if shipping_method not in SHIPPING_METHODS:
            flash('Metode pengiriman tidak valid!', 'danger')
            return redirect(url_for('checkout'))

        for pid, qty in cart.items():
            product = Product.query.get(int(pid))
            if product:
                transaction = Transaction(
                    user_id=current_user.id,
                    product_id=product.id,
                    quantity=qty,
                    total_price=product.price * qty,
                    payment_method=payment_method,
                    shipping_method=shipping_method,
                    status='pending'
                )
                db.session.add(transaction)
        db.session.commit()
        session['cart'] = {}
        flash('Checkout berhasil! Pesanan dibuat.', 'success')
        return redirect(url_for('index'))
    return render_template('checkout.html', payment_methods=PAYMENT_METHODS, shipping_methods=SHIPPING_METHODS)

# ===== Transaction History =====
@app.route('/transactions')
@login_required
def transaction_history():
    transactions = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.created_at.desc()).all()
    return render_template('transactions.html', transactions=transactions)

# ===== Upload Payment Proof =====
@app.route('/upload_payment/<int:transaction_id>', methods=['POST'])
@login_required
def upload_payment(transaction_id):
    transaction = Transaction.query.get_or_404(transaction_id)
    if transaction.user_id != current_user.id:
        flash('Akses ditolak!', 'danger')
        return redirect(url_for('index'))

    file = request.files.get('payment_proof')
    if file and file.filename != '':
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        transaction.payment_proof = filename
        db.session.commit()
        flash('Bukti pembayaran berhasil diunggah!', 'success')
    else:
        flash('Tidak ada file yang dipilih.', 'warning')
    return redirect(url_for('transaction_history'))

# ===== Admin Update Transaction Status =====
@app.route('/admin/update_transaction/<int:transaction_id>', methods=['POST'])
@login_required
def update_transaction(transaction_id):
    if current_user.role != 'admin':
        flash('Akses ditolak!', 'danger')
        return redirect(url_for('index'))
    
    transaction = Transaction.query.get_or_404(transaction_id)
    status = request.form['status']
    if status in ['pending', 'processing', 'shipped', 'completed', 'cancelled']:
        transaction.status = status
        db.session.commit()
        flash('Status transaksi diperbarui!', 'success')
    else:
        flash('Status tidak valid!', 'danger')
    return redirect(url_for('admin_dashboard'))

# ===== Jalankan Aplikasi =====
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

