from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from datetime import datetime
import os
import midtransclient

# ===== Konfigurasi Aplikasi =====
class Config:
    SECRET_KEY = 'supersecretkey123'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///abdull908761989.db'
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

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), default='user')
    
    # Data alamat
    alamat = db.Column(db.String(250))
    rt = db.Column(db.String(10))
    rw = db.Column(db.String(10))
    kecamatan = db.Column(db.String(100))
    kelurahan = db.Column(db.String(100))
    kota = db.Column(db.String(100))          # Tambahan
    provinsi = db.Column(db.String(100))
    kode_pos = db.Column(db.String(10))       # Tambahan
    no_telepon = db.Column(db.String(20))     # Tambahan
    
    is_verified = db.Column(db.Boolean, default=False)

    # Relasi ke tabel transaksi
    transactions = db.relationship('Transaction', backref='user', lazy=True)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Float, nullable=False)
    image = db.Column(db.String(150))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    category = db.Column(db.String(50), default='biasa')  # pilihan, unggulan, preorder
    stock = db.Column(db.Integer, default=0)
    weight = db.Column(db.Float, default=0.0)  # <=== Kolom berat (dalam kg atau gram sesuai kebutuhan)
    is_active = db.Column(db.Boolean, default=True)
    is_featured = db.Column(db.Boolean, default=False)   # produk unggulan
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
    products = Product.query.filter_by(is_active=True).all()
    return render_template('user-dashboard.html', user=current_user, products=products)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.form
        email = data['email'].lower()
        existing_user = User.query.filter_by(email=email).first()

        # Cek email sudah terdaftar dan terverifikasi
        if existing_user and existing_user.is_verified:
            flash("Email sudah terdaftar dan diverifikasi! Gunakan email lain.", "danger")
            return redirect(url_for('register'))

        # Tentukan role
        requested_role = data.get('role', 'user')
        admin_count = User.query.filter_by(role='admin').count()
        role = 'admin' if requested_role == 'admin' and admin_count < 4 else 'user'

        # Hash password
        hashed_password = generate_password_hash(data['password'], method='scrypt')

        # Jika email sudah ada tapi belum diverifikasi, hapus data lama
        if existing_user and not existing_user.is_verified:
            db.session.delete(existing_user)
            db.session.commit()
            flash("Email belum diverifikasi sebelumnya. Data lama dihapus, silakan cek email baru.", "info")

        # Buat user baru dengan tambahan field: no_telepon, kota, kode_pos
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
            kota=data.get('kota'),              # Tambahan
            provinsi=data.get('provinsi'),
            kode_pos=data.get('kode_pos'),      # Tambahan
            no_telepon=data.get('no_telepon'),  # Tambahan
            is_verified=False
        )
        db.session.add(user)
        db.session.commit()

        # Jika user adalah admin, simpan log admin
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
        except Exception as e:
            print("Error kirim email:", e)
            flash(f'Registrasi berhasil! Role: {role}. Email verifikasi gagal dikirim, silakan login. (Error di-skip)', 'warning')

        return redirect(url_for('login'))

    # GET request → tampilkan halaman register
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
        category = request.form.get('category', 'biasa')
        stock = int(request.form.get('stock', 0))

        # Ambil berat dari form
        try:
            weight = float(request.form.get('weight', 0.0))
        except ValueError:
            weight = 0.0

        # Default untuk produk preorder
        if category == 'preorder' and stock == 0:
            stock = 10

        # Proses gambar
        image_file = request.files.get('image')
        filename = None
        if image_file and image_file.filename != '':
            filename = secure_filename(image_file.filename)
            image_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        # Simpan ke database
        product = Product(
            name=name,
            description=description,
            price=price,
            weight=weight,  # <=== Tambahkan berat
            image=filename,
            category=category,
            stock=stock,
            is_active=True
        )
        db.session.add(product)
        db.session.commit()

        flash('Produk berhasil ditambahkan!', 'success')
        return redirect(url_for('add_product'))

    products = Product.query.all()
    return render_template('add_product.html', products=products)

@app.route('/admin/toggle_product/<int:product_id>')
@login_required
def toggle_product(product_id):
    if current_user.role != 'admin':
        flash('Akses ditolak!', 'danger')
        return redirect(url_for('index'))
    product = Product.query.get_or_404(product_id)
    product.is_active = not product.is_active
    db.session.commit()
    flash(f'Status produk "{product.name}" diubah menjadi {"Aktif" if product.is_active else "Nonaktif"}.', 'info')
    return redirect(url_for('admin_dashboard'))

# ===== Product Routes =====
@app.route('/product/<int:product_id>')
@login_required
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    return render_template('product_detail.html', product=product)

@app.route('/products/pilihan')
@login_required
def products_pilihan():
    products = Product.query.filter_by(category='pilihan', is_active=True).all()
    return render_template('products_list.html', title="Produk Pilihan", products=products)

@app.route('/products/unggulan')
@login_required
def products_unggulan():
    products = Product.query.filter_by(category='unggulan', is_active=True).all()
    return render_template('products_list.html', title="Produk Unggulan", products=products)

@app.route('/products/preorder')
@login_required
def products_preorder():
    products = Product.query.filter_by(category='preorder', is_active=True).all()
    return render_template('products_list.html', title="Produk Pre-Order", products=products)

# ===== Cart =====
@app.route('/add_to_cart/<int:product_id>', methods=['GET'])
@login_required
def add_to_cart(product_id):
    qty = request.args.get('quantity', 1)
    try:
        qty = int(qty)
        if qty < 1:
            qty = 1
    except ValueError:
        qty = 1

    cart = get_cart()
    cart[str(product_id)] = cart.get(str(product_id), 0) + qty
    save_cart(cart)
    flash(f'Produk ditambahkan ke keranjang ({qty} pcs)!', 'success')
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

# ===== Checkout =====
# ===== Checkout dengan Midtrans Gabungan =====

@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    # Ambil keranjang dari session
    cart = session.get('cart', {})
    if not cart:
        flash("Keranjang kosong!", "warning")
        return redirect(url_for('index'))

    # Ambil semua produk di cart
    products = []
    total = 0
    for pid, qty in cart.items():
        product = Product.query.get(int(pid))
        if product:
            subtotal = product.price * qty
            products.append({
                'product': product,
                'qty': qty,
                'subtotal': subtotal
            })
            total += subtotal

    # Ambil data user
    user = current_user

    if request.method == 'POST':
        shipping_method = request.form.get('shipping_method')
        if shipping_method not in SHIPPING_METHODS:
            flash('Metode pengiriman tidak valid!', 'danger')
            return redirect(url_for('checkout'))

        # Buat transaksi di DB
        transaction_items = []
        for item in products:
            product = item['product']
            qty = item['qty']

            # Cek stok
            if product.category != 'preorder' and product.stock < qty:
                flash(f"Stok {product.name} tidak mencukupi!", "danger")
                return redirect(url_for('view_cart'))

            # Update stok
            if product.category != 'preorder':
                product.stock -= qty
                if product.stock <= 0:
                    product.is_active = False

            # Simpan transaksi
            transaction = Transaction(
                user_id=user.id,
                product_id=product.id,
                quantity=qty,
                total_price=product.price * qty,
                payment_method='Midtrans',
                shipping_method=shipping_method,
                status='pending',
                phone=user.phone,          # Nomor telepon
                kota=user.kota,            # Kota
                kode_pos=user.kode_pos     # Kode pos
            )
            db.session.add(transaction)
            transaction_items.append(transaction)

        db.session.commit()

        # ===== Midtrans Snap Token =====
        client = midtransclient.Snap(
            is_production=False,
            server_key='YOUR_SERVER_KEY',
            client_key='YOUR_CLIENT_KEY'
        )

        order_id = f"ORDER-{user.id}-{int(datetime.utcnow().timestamp())}"
        transaction_details = {
            "order_id": order_id,
            "gross_amount": total
        }

        item_details = []
        for item in products:
            item_details.append({
                "id": str(item['product'].id),
                "price": item['product'].price,
                "quantity": item['qty'],
                "name": item['product'].name
            })

        customer_details = {
            "first_name": user.name,
            "email": user.email,
            "phone": user.phone or "081234567890",
            "billing_address": {
                "first_name": user.name,
                "address": user.alamat,
                "city": user.kota or user.kecamatan,
                "postal_code": user.kode_pos or "00000",
                "phone": user.phone or "081234567890",
                "country_code": "IDN"
            }
        }

        snap_payload = {
            "transaction_details": transaction_details,
            "item_details": item_details,
            "customer_details": customer_details,
            "enabled_payments": ["gopay","bank_transfer","credit_card","shopeepay","qris"],
            "credit_card": {"secure": True}
        }

        snap_response = client.create_transaction(snap_payload)
        snap_token = snap_response['token']

        # Kosongkan cart
        session['cart'] = {}
        flash('Checkout berhasil! Silakan lanjutkan pembayaran.', 'success')
        return render_template('midtrans_payment.html', snap_token=snap_token, total=total, order_id=order_id)

    # GET request, tampilkan halaman checkout
    return render_template(
        'checkout.html',
        products=products,
        total=total,
        user=user,
        shipping_methods=SHIPPING_METHODS
    )

@app.route('/buy_now/<int:product_id>')
@login_required
def buy_now(product_id):
    qty = int(request.args.get('quantity', 1))
    cart = session.get('cart', {})
    cart[str(product_id)] = qty
    session['cart'] = cart

    print("DEBUG: Cart now =", session['cart'])  # Tambahkan ini
    flash("Berhasil ditambahkan, lanjut ke checkout...", "success")

    return redirect(url_for('checkout'))

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

@app.route('/admin/update_stock/<int:product_id>', methods=['POST'])
@login_required
def update_stock(product_id):
    if current_user.role != 'admin':
        flash('Akses ditolak!', 'danger')
        return redirect(url_for('index'))
    product = Product.query.get_or_404(product_id)
    try:
        new_stock = int(request.form['stock'])
        product.stock = new_stock
        db.session.commit()
        flash('Stok produk berhasil diperbarui!', 'success')
    except ValueError:
        flash('Input stok tidak valid!', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/toggle_featured/<int:product_id>', methods=['POST'])
@login_required
def toggle_featured(product_id):
    if current_user.role != 'admin':
        flash('Akses ditolak!', 'danger')
        return redirect(url_for('index'))
    product = Product.query.get_or_404(product_id)
    product.is_featured = not product.is_featured
    db.session.commit()
    flash(f'Produk "{product.name}" berhasil {"ditandai sebagai unggulan" if product.is_featured else "dihapus dari unggulan"}!', 'info')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/update_status/<int:transaction_id>', methods=['POST'])
@login_required
def update_status(transaction_id):
    if current_user.role != 'admin':
        flash('Akses ditolak!', 'danger')
        return redirect(url_for('index'))
    transaction = Transaction.query.get_or_404(transaction_id)
    status = request.form.get('status')
    if status in ['pending', 'processing', 'shipped', 'completed', 'cancelled']:
        transaction.status = status
        db.session.commit()
        flash('Status transaksi diperbarui!', 'success')
    else:
        flash('Status tidak valid!', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/payment/success/<order_id>')
@login_required
def payment_success(order_id):
    transaction = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.id.desc()).first()
    if transaction:
        transaction.status = 'success'
        db.session.commit()
    flash('Pembayaran berhasil!', 'success')
    return redirect(url_for('index'))

@app.route('/payment/pending/<order_id>')
@login_required
def payment_pending(order_id):
    flash('Pembayaran pending. Silakan selesaikan pembayaran Anda.', 'info')
    return redirect(url_for('index'))

@app.route('/admin/delete_product/<int:product_id>', methods=['POST'])
@login_required
def delete_product(product_id):
    if current_user.role != 'admin':
        abort(403)
    product = Product.query.get_or_404(product_id)
    db.session.delete(product)
    db.session.commit()
    flash('Produk berhasil dihapus', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/toggle_active/<int:product_id>', methods=['POST'])
@login_required
def toggle_active(product_id):
    product = Product.query.get_or_404(product_id)
    product.is_active = not product.is_active
    db.session.commit()
    flash("Status produk diperbarui!", "success")
    return redirect(url_for('admin_dashboard'))

# ===== Jalankan Aplikasi =====
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
