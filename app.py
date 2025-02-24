from flask import Flask, request, render_template, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os

# Inicjalizacja aplikacji Flask
app = Flask(__name__, template_folder="templates")
app.secret_key = 'tajny_klucz'  # Klucz do szyfrowania sesji

# Konfiguracja bazy danych (PostgreSQL z Render)
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://magazyn_user:FH1mT4UHJvVrqmXXfQz6koc6FnVB3szQ@dpg-cuovb9ggph6c73dqpvc0-a/magazyn"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Inicjalizacja SQLAlchemy
db = SQLAlchemy(app)

# --------------------------
# Modele dla modułu zamówień
# --------------------------

class Client(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    orders = db.relationship('Order', backref='client', lazy=True, cascade="all, delete-orphan")
    products = db.relationship('ClientProduct', backref='client', lazy=True, cascade="all, delete-orphan")

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_date = db.Column(db.Date, nullable=True)
    shipment_date = db.Column(db.Date, nullable=True)
    is_archived = db.Column(db.Boolean, default=False)
    invoice_number = db.Column(db.String(50), nullable=True)
    client_id = db.Column(db.Integer, db.ForeignKey('client.id'), nullable=False)
    products = db.relationship('OrderProduct', backref='order', lazy=True, cascade="all, delete-orphan")

class ClientProduct(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    client_id = db.Column(db.Integer, db.ForeignKey('client.id'), nullable=False)

class OrderProduct(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    quantity_ordered = db.Column(db.Integer, nullable=False, default=0)
    quantity_packed = db.Column(db.Integer, nullable=False, default=0)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)

# --------------------------
# Modele dla modułu magazynu
# --------------------------

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    products = db.relationship('Product', backref='category', lazy=True, cascade="all, delete-orphan")

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id', ondelete='CASCADE'), nullable=False)

# --------------------------
# Tworzenie bazy danych
# --------------------------

with app.app_context():
    db.create_all()

# --------------------------
# Wspólny system logowania
# --------------------------

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "magazyn12"

# Endpoint do wyświetlenia strony logowania (GET)
@app.route('/login', methods=['GET'])
def login_page():
    return render_template('index.html')  # Użyj tego samego pliku HTML do logowania

# Endpoint do obsługi logowania (POST)
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    if data.get("username") == ADMIN_USERNAME and data.get("password") == ADMIN_PASSWORD:
        session["user"] = ADMIN_USERNAME
        return jsonify({"redirect": url_for("orders"), "message": "Login successful"})
    return jsonify({"message": "Invalid credentials"}), 401

# Endpoint do wylogowania (GET)
@app.route('/logout', methods=['GET'])
def logout():
    session.clear()
    return redirect(url_for('login_page'))  # Przekieruj do strony logowania

# --------------------------
# Endpointy dla modułu zamówień
# --------------------------

@app.route('/')
def home():
    if 'user' in session:
        clients = Client.query.all()
        active_orders = Order.query.filter_by(is_archived=False).all()
        return render_template('index1.html', username=session['user'], clients=clients, active_orders=active_orders)
    return redirect(url_for('login_page'))
    
@app.route('/orders')
def orders():
    if 'user' in session:
        clients = Client.query.all()
        active_orders = Order.query.filter_by(is_archived=False).all()
        return render_template('index1.html', username=session['user'], clients=clients, active_orders=active_orders)
    return redirect(url_for('login_page'))
    
@app.route('/add_client', methods=['POST'])
def add_client():
    if 'user' not in session:
        return redirect(url_for('home'))

    name = request.form.get('name')
    if name:
        new_client = Client(name=name)
        db.session.add(new_client)
        db.session.commit()

    return redirect(url_for('home'))

@app.route('/delete_client/<int:client_id>', methods=['POST'])
def delete_client(client_id):
    if 'user' not in session:
        return redirect(url_for('home'))

    client = Client.query.get_or_404(client_id)
    db.session.delete(client)
    db.session.commit()

    return redirect(url_for('home'))

@app.route('/client/<int:client_id>')
def client_details(client_id):
    client = Client.query.get_or_404(client_id)
    archived_orders = Order.query.filter_by(client_id=client.id, is_archived=True).order_by(Order.order_date.desc()).all()
    return render_template('client_details.html', client=client, archived_orders=archived_orders)

@app.route('/add_order/<int:client_id>', methods=['POST'])
def add_order(client_id):
    if 'user' not in session:
        return redirect(url_for('home'))

    order_date_str = request.form.get('order_date')
    order_date = datetime.strptime(order_date_str, '%Y-%m-%d').date() if order_date_str else None

    new_order = Order(
        order_date=order_date,
        client_id=client_id
    )
    db.session.add(new_order)
    db.session.commit()

    client = Client.query.get_or_404(client_id)
    for client_product in client.products:
        order_product = OrderProduct(
            name=client_product.name,
            quantity_ordered=0,
            quantity_packed=0,
            order_id=new_order.id
        )
        db.session.add(order_product)
    db.session.commit()

    return redirect(url_for('order_details', order_id=new_order.id))

@app.route('/order/<int:order_id>')
def order_details(order_id):
    order = Order.query.get_or_404(order_id)
    return render_template('order_details.html', order=order)

@app.route('/add_product/<int:client_id>', methods=['POST'])
def add_product(client_id):
    if 'user' not in session:
        return redirect(url_for('home'))

    product_name = request.form.get('product_name')
    if product_name:
        new_product = ClientProduct(
            name=product_name,
            client_id=client_id
        )
        db.session.add(new_product)
        db.session.commit()

    return redirect(url_for('client_details', client_id=client_id))

@app.route('/delete_client_product/<int:product_id>', methods=['POST'])
def delete_client_product(product_id):
    if 'user' not in session:
        return redirect(url_for('home'))

    product = ClientProduct.query.get_or_404(product_id)
    client_id = product.client_id
    db.session.delete(product)
    db.session.commit()

    return redirect(url_for('client_details', client_id=client_id))

@app.route('/update_product_quantity/<int:product_id>', methods=['POST'])
def update_product_quantity(product_id):
    if 'user' not in session:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403

    product = OrderProduct.query.get_or_404(product_id)
    data = request.get_json()

    if 'quantity_ordered' in data:
        product.quantity_ordered = int(data['quantity_ordered'])
    if 'quantity_packed' in data:
        product.quantity_packed = int(data['quantity_packed'])

    db.session.commit()
    return jsonify({'success': True})

@app.route('/delete_order_product/<int:product_id>', methods=['POST'])
def delete_order_product(product_id):
    if 'user' not in session:
        return redirect(url_for('home'))

    product = OrderProduct.query.get_or_404(product_id)
    order_id = product.order_id
    db.session.delete(product)
    db.session.commit()

    return redirect(url_for('order_details', order_id=order_id))

@app.route('/update_shipment_date/<int:order_id>', methods=['POST'])
def update_shipment_date(order_id):
    if 'user' not in session:
        return redirect(url_for('home'))

    order = Order.query.get_or_404(order_id)
    shipment_date_str = request.form.get('shipment_date')

    order.shipment_date = datetime.strptime(shipment_date_str, '%Y-%m-%d').date() if shipment_date_str else None
    db.session.commit()

    return redirect(url_for('order_details', order_id=order_id))

@app.route('/complete_order/<int:order_id>', methods=['POST'])
def complete_order(order_id):
    if 'user' not in session:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403

    order = Order.query.get_or_404(order_id)
    order.is_archived = True
    db.session.commit()

    return jsonify({'success': True})

@app.route('/update_invoice_number/<int:order_id>', methods=['POST'])
def update_invoice_number(order_id):
    if 'user' not in session:
        return redirect(url_for('home'))

    order = Order.query.get_or_404(order_id)
    invoice_number = request.form.get('invoice_number')

    order.invoice_number = invoice_number
    db.session.commit()

    return redirect(url_for('order_details', order_id=order_id))

@app.route('/delete_archived_order/<int:order_id>', methods=['POST'])
def delete_archived_order(order_id):
    if 'user' not in session:
        return redirect(url_for('home'))

    order = Order.query.get_or_404(order_id)
    client_id = order.client_id
    db.session.delete(order)
    db.session.commit()

    return redirect(url_for('client_details', client_id=client_id))

# --------------------------
# Endpointy dla modułu magazynu
# --------------------------

@app.route("/categories", methods=["GET"])
def get_categories():
    categories = Category.query.all()
    return jsonify([{"id": c.id, "name": f"{c.name} (Cat. ID: {c.id})"} for c in categories])

@app.route("/products", methods=["GET"])
def get_products():
    categories = Category.query.all()
    products_by_category = {}
    
    for category in categories:
        products = Product.query.filter_by(category_id=category.id).all()
        products_by_category[f"{category.name} (Cat. ID: {category.id})"] = [
            {"id": p.id, "name": p.name, "quantity": p.quantity, "category_id": p.category_id}
            for p in products
        ]
    
    return jsonify(products_by_category)

@app.route("/category", methods=["POST"])
def add_category():
    data = request.json
    new_category = Category(name=data.get("name"))
    db.session.add(new_category)
    db.session.commit()
    return jsonify({"message": "Category added successfully!"})

@app.route("/category/<int:category_id>", methods=["PUT"])
def update_category(category_id):
    data = request.json
    category = Category.query.get_or_404(category_id)
    category.name = data.get("name")
    db.session.commit()
    return jsonify({"message": "Category updated successfully!"})

@app.route("/category/<int:category_id>", methods=["DELETE"])
def delete_category(category_id):
    category = Category.query.get_or_404(category_id)
    Product.query.filter_by(category_id=category_id).delete()
    db.session.delete(category)
    db.session.commit()
    return jsonify({"message": "Category deleted successfully!"})

@app.route("/product", methods=["POST"])
def add_warehouse_product():
    data = request.json
    
    if not data.get("name") or not isinstance(data.get("quantity"), int) or not isinstance(data.get("category_id"), int):
        return jsonify({"message": "Invalid data! Ensure all fields are filled correctly."}), 400

    new_product = Product(
        name=data["name"].strip(),
        quantity=int(data["quantity"]),
        category_id=int(data["category_id"])
    )

    db.session.add(new_product)
    db.session.commit()
    
    return jsonify({"message": "Product added successfully!"})

@app.route("/product/<int:product_id>", methods=["PUT"])
def update_product(product_id):
    data = request.json
    product = Product.query.get_or_404(product_id)
    product.name = data.get("name")
    product.quantity = data.get("quantity")
    
    if "category_id" in data and data.get("category_id") is not None:
        product.category_id = data.get("category_id")
    
    db.session.commit()
    return jsonify({"message": "Product updated successfully!"})

@app.route("/product/<int:product_id>", methods=["DELETE"])
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    db.session.delete(product)
    db.session.commit()
    return jsonify({"message": "Product deleted successfully!"})

# --------------------------
# Uruchomienie aplikacji
# --------------------------

if __name__ == "__main__":
    app.run(debug=True)
