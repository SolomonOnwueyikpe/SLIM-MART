from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.utils import secure_filename
import os

app = Flask(__name__, static_folder='static')
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ecommerce.db'
app.config['JWT_SECRET_KEY'] = 'anothersecretkey'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String, unique=True, nullable=False)
    fname = db.Column(db.String, nullable=False)
    lname = db.Column(db.String, nullable=False)
    email = db.Column(db.String, unique=True, nullable=False)
    phone = db.Column(db.String, unique=True, nullable=False)
    password_hash = db.Column(db.String, nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, unique=True, nullable=False)
    users = db.relationship('User', backref='role', lazy=True)

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, unique=True, nullable=False)
    products = db.relationship('Product', backref='category', lazy=True)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    description = db.Column(db.String, nullable=False)
    price = db.Column(db.Float, nullable=False)
    stock = db.Column(db.Integer, nullable=False)
    feature = db.Column(db.Integer, nullable=False, default=0)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='product.jpg')

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    total_price = db.Column(db.Float, nullable=False)
    purchased = db.Column(db.Integer, nullable=False)
    user = db.relationship('User', backref='orders')
    product = db.relationship('Product', backref='orders')

class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    total_price = db.Column(db.Float, nullable=False)
    user = db.relationship('User', backref='carts')
    product = db.relationship('Product', backref='carts')

# Initialize database
with app.app_context():
    def create_tables():
        db.create_all()
        # Create default roles
        if not Role.query.filter_by(name='user').first():
            db.session.add(Role(name='user'))
            db.session.add(Role(name='admin'))
            db.session.commit()
        # Create default categories if they don't exist
        if not Category.query.filter_by(name='Jewelries').first():
            db.session.add(Category(name='Jewelries'))
            db.session.add(Category(name='Electronics'))
            db.session.add(Category(name='Books'))
            db.session.add(Category(name='Foods'))
            db.session.add(Category(name='Household'))
            db.session.add(Category(name='Clothes'))            
            db.session.commit()
        # Create super admin
        if not User.query.filter_by(role_id=2).first():
            db.session.add(User(fname='john',lname='rambo',email='john.rambo@yopmail.com',phone='08034504455',uuid=os.urandom(16).hex(),password='Thefirst@blood',role_id=2,image_file='default.jpg'))
            db.session.commit()
        # Add seed products
        if not Product.query.filter_by(name='laptop').first():
            db.session.add(Product(name='laptop',description='A nice and simple hp laptop',price=250000,stock=7,feature=1,category_id=2,image_file='laptop.jpg'))
            db.session.add(Product(name='phone',description='A nice and simple phone',price=210000,stock=4,feature=1,category_id=2,image_file='phone.jpg'))
            db.session.add(Product(name='de luxe table',description='A nice and beautiful table',price=20000,stock=10,feature=1,category_id=5,image_file='table.jpg'))
            db.session.add(Product(name='belt',description='A beautiful belt',price=4000,stock=17,feature=0,category_id=6,image_file='belt.jpg'))
            db.session.add(Product(name='cake',description='A delicacy for everyone',price=8000,stock=12,feature=1,category_id=4,image_file='cake.jpg'))
            db.session.commit()
    create_tables()

# Web Routes
@app.route('/' , methods=['GET'])
def home():

    if request.args:
        cat_id = int(request.args['cat_id'])
    else:
        cat_id = 0
    products = Product.query.filter_by(feature=1).all()
    if cat_id == 0:
        product_extras = Product.query.all()
    else:
        product_extras = Product.query.filter_by(category_id=cat_id).all()
    categories = Category.query.all()
    user = 0
    if session and 'user_id' in session:
        current_user_id = session['user_id']
        user = User.query.get(current_user_id)
    
    return render_template('home.html', products=products,product_extras=product_extras,User=user,categories=categories)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.form
        new_user = User(
            uuid=os.urandom(16).hex(),
            fname=data['fname'],
            lname=data['lname'],
            email=data['email'],
            phone=data['phone'],
            password=data['password'],
            role_id=Role.query.filter_by(name='user').first().id
        )
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', User=User)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.form
        user = User.query.filter_by(email=data['email']).first()
        if user and user.check_password(data['password']):
            access_token = create_access_token(identity=user.id)
            session['access_token'] = access_token
            session['user_id'] = user.id
            session['uuid'] = user.uuid
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid credentials!', 'danger')
    return render_template('login.html')


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' in session:
        current_user_id = session['user_id']
        user = User.query.get(current_user_id)
        if request.method == 'POST':
            if 'image' in request.files:
                image = request.files['image']
                if image.filename != '':
                    filename = secure_filename(image.filename)
                    # Save the image to the profile_pics directory
                    image_path = os.path.join(app.root_path, 'static/profile_pics', filename)
                    image.save(image_path)
                    # Update user's image file in the database
                    user.image_file = filename
                    db.session.commit()
                    flash('Your profile picture has been updated!', 'success')
        orders = user.orders
        return render_template('profile.html', user=user, orders=orders, User=User)
    else:
        return redirect(url_for('login'))
    

@app.route('/cart/<int:product_id>', methods=['GET', 'POST'])
def product_detail(product_id):
    product = Product.query.get(product_id)
    if request.method == 'POST':
        if 'access_token' not in session:
            flash('Please log in to place an order.', 'warning')
            return redirect(url_for('login'))
        quantity = int(request.form['quantity'])
        if quantity > product.stock:
            flash('Not enough stock!', 'danger')
            return redirect(url_for('product_detail', product_id=product_id))
        current_user_id = session['user_id']
        total_price = quantity * product.price
        new_order = Order(
            user_id=current_user_id,
            product_id=product_id,
            quantity=quantity,
            total_price=total_price
        )
        product.stock -= quantity
        db.session.add(new_order)
        db.session.commit()
        flash('Order placed successfully!', 'success')
        return redirect(url_for('cart'))
    return render_template('product_detail.html', product=product)


@app.route('/cart', methods=['GET', 'POST'])
def cart():
    if 'user_id' in session:
        current_user_id = session['user_id']
        cart_items = Cart.query.filter_by(user_id=current_user_id).all()
        return render_template('cart.html', cart_items=cart_items)
    else:
        flash('Please log in to view your cart.', 'warning')
        return redirect(url_for('login'))

@app.route('/cart/add/<int:product_id>', methods=['GET','POST'])
def add_to_cart(product_id):
    if 'user_id' in session:
        current_user_id = session['user_id']
        product = Product.query.get(product_id)
        quantity = int(request.form['quantity'])
        total_price = quantity * product.price
        cart_item = Cart.query.filter_by(user_id=current_user_id, product_id=product_id).first()
        if cart_item:
            cart_item.quantity += quantity
            cart_item.total_price += total_price
        else:
            cart_item = Cart(
                user_id=current_user_id,
                product_id=product_id,
                quantity=quantity,
                total_price=total_price
            )
            db.session.add(cart_item)
        db.session.commit()
        flash('Item added to cart!', 'success')
        return redirect(url_for('cart'))
    else:
        flash('Please log in to add items to your cart.', 'warning')
        return redirect(url_for('login'))

@app.route('/cart/remove/<int:cart_item_id>', methods=['POST'])
def remove_from_cart(cart_item_id):
    if 'user_id' in session:
        cart_item = Cart.query.get(cart_item_id)
        db.session.delete(cart_item)
        db.session.commit()
        flash('Item removed from cart!', 'success')
        return redirect(url_for('cart'))
    else:
        flash('Please log in to remove items from your cart.', 'warning')
        return redirect(url_for('login'))

@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    if 'user_id' in session:
        current_user_id = session['user_id']
        cart_items = Cart.query.filter_by(user_id=current_user_id).all()
        total_amount = sum(item.total_price for item in cart_items)

        if request.method == 'POST':
            # Here you would handle the payment processing logic
            # For simplicity, we'll just clear the cart and show a success message
            for item in cart_items:
                product = Product.query.get(item.product_id)
                product.stock -= item.quantity
                db.session.delete(item)
                order = Order(
                user_id=current_user_id,
                product_id=item.product_id,
                quantity=item.quantity,
                total_price=item.total_price,
                purchased=1
                )
                db.session.add(order)
            db.session.commit()
            flash('Purchase successful! Thank you for your order.', 'success')
            return redirect(url_for('home'))

        return render_template('checkout.html', cart_items=cart_items, total_amount=total_amount)
    else:
        flash('Please log in to proceed to checkout.', 'warning')
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    if 'access_token' in session or 'user_id' in session:
        session.pop('access_token', None)
        session.pop('user_id', None)
    flash('Logged out successfully!', 'success')
    return redirect(url_for('home'))

@app.route('/admin')
def admin():
    if session and session['user_id'] is not None:
        current_user_id = session['user_id']
        user = User.query.get(current_user_id)
        if user.role.name != 'admin':
            flash('Unauthorized access!', 'danger')
            return redirect(url_for('home'))
        products = Product.query.all()
        orders = Order.query.all()
        return render_template('admin.html', products=products, User=User, orders=orders)
    else:
        return redirect(url_for('home'))




@app.route('/admin/add_product', methods=['GET', 'POST'])
def add_product():
    if 'user_id' in session:
        current_user_id = session['user_id']
        user = User.query.get(current_user_id)
        if user.role.name != 'admin':
            flash('Unauthorized access!', 'danger')
            return redirect(url_for('home'))
        if request.method == 'POST':
            data = request.form
            if 'image' in request.files:
                image = request.files['image']
                if image.filename != '':
                    filename = secure_filename(image.filename)
                    # Save the image to the profile_pics directory
                    image_path = os.path.join(app.root_path, 'static/product_pics', filename)
                    image.save(image_path)

            new_product = Product(
                name=data['name'],
                description=data['description'],
                price=float(data['price']),
                stock=int(data['stock']),
                category_id=int(data['category']),
                image_file=filename
            )
            db.session.add(new_product)
            db.session.commit()
            flash('Product added successfully!', 'success')
            return redirect(url_for('admin'))
        categories = Category.query.all()
        return render_template('add_product.html', categories=categories)
    else:
        return redirect(url_for('admin'))




@app.route('/admin/profile', methods=['GET', 'POST'])
def profile_admin():
    if 'user_id' in session:
        current_user_id = session['user_id']
        user = User.query.get(current_user_id)
        if user.role.name != 'admin':
            flash('Unauthorized access!', 'danger')
            return redirect(url_for('admin'))
        if request.method == 'POST':
            if 'image' in request.files:
                image = request.files['image']
                if image.filename != '':
                    filename = secure_filename(image.filename)
                    # Save the image to the profile_pics directory
                    image_path = os.path.join(app.root_path, 'static/profile_pics', filename)
                    image.save(image_path)
                    # Update user's image file in the database
                    user.image_file = filename
                    db.session.commit()
                    flash('Your profile picture has been updated!', 'success')
        orders = user.orders
        return render_template('profile_admin.html', user=user, orders=orders, User=User)
    else:
        return redirect(url_for('login'))
    



if __name__ == '__main__':
    app.run(debug=True)
