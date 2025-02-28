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
    quantity_ordered = db.Column(db.Integer, nullable=False, default=0)  # Zamówiono
    wykulane = db.Column(db.Integer, nullable=False, default=0)  # Wykulane
    quantity_packed = db.Column(db.Integer, nullable=False, default=0)  # Spakowano
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
        session["user"] = ADMIN_USERNAME  # Ustawienie sesji
        module = data.get("module", "orders")  # Domyślnie zamówienia, jeśli moduł nie jest wybrany
        session["module"] = module  # Zapisz wybrany moduł w sesji

        if module == "warehouse":
            return jsonify({"redirect": url_for("warehouse_home"), "message": "Login successful"})  # Przekieruj do magazynu
        else:
            return jsonify({"redirect": url_for("orders"), "message": "Login successful"})  # Przekieruj do zamówień
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
        if session.get("module") == "warehouse":
            return redirect(url_for("warehouse_home"))  # Przekieruj do magazynu
        else:
            return redirect(url_for("orders"))  # Przekieruj do zamówień
    return redirect(url_for('login_page'))

@app.route('/orders')
def orders():
    if 'user' in session and session.get("module") == "orders":
        clients = Client.query.all()
        active_orders = Order.query.filter_by(is_archived=False).all()
        return render_template('index1.html', username=session['user'], clients=clients, active_orders=active_orders)
    else:
        return redirect(url_for('logout'))  # Wyloguj, jeśli użytkownik próbuje wejść do niewłaściwego modułu

# Reszta endpointów dla modułu zamówień pozostaje bez zmian...

# --------------------------
# Endpointy dla modułu magazynu
# --------------------------

@app.route('/warehouse')
def warehouse_home():
    if 'user' in session and session.get("module") == "warehouse":
        return render_template('index.html', username=session['user'])
    else:
        return redirect(url_for('logout'))  # Wyloguj, jeśli użytkownik próbuje wejść do niewłaściwego modułu

@app.route("/categories", methods=["GET"])
def get_categories():
    if 'user' not in session or session.get("module") != "warehouse":
        return redirect(url_for('logout'))  # Wyloguj, jeśli użytkownik próbuje wejść do niewłaściwego modułu

    categories = Category.query.all()
    return jsonify([{"id": c.id, "name": f"{c.name} (Cat. ID: {c.id})"} for c in categories])

@app.route("/products", methods=["GET"])
def get_products():
    if 'user' not in session or session.get("module") != "warehouse":
        return redirect(url_for('logout'))  # Wyloguj, jeśli użytkownik próbuje wejść do niewłaściwego modułu

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
    if 'user' not in session or session.get("module") != "warehouse":
        return redirect(url_for('logout'))  # Wyloguj, jeśli użytkownik próbuje wejść do niewłaściwego modułu

    data = request.json
    new_category = Category(name=data.get("name"))
    db.session.add(new_category)
    db.session.commit()
    return jsonify({"message": "Category added successfully!"})

@app.route("/category/<int:category_id>", methods=["PUT"])
def update_category(category_id):
    if 'user' not in session or session.get("module") != "warehouse":
        return redirect(url_for('logout'))  # Wyloguj, jeśli użytkownik próbuje wejść do niewłaściwego modułu

    data = request.json
    category = Category.query.get_or_404(category_id)
    category.name = data.get("name")
    db.session.commit()
    return jsonify({"message": "Category updated successfully!"})

@app.route("/category/<int:category_id>", methods=["DELETE"])
def delete_category(category_id):
    if 'user' not in session or session.get("module") != "warehouse":
        return redirect(url_for('logout'))  # Wyloguj, jeśli użytkownik próbuje wejść do niewłaściwego modułu

    category = Category.query.get_or_404(category_id)
    Product.query.filter_by(category_id=category_id).delete()
    db.session.delete(category)
    db.session.commit()
    return jsonify({"message": "Category deleted successfully!"})

@app.route("/product", methods=["POST"])
def add_warehouse_product():
    if 'user' not in session or session.get("module") != "warehouse":
        return redirect(url_for('logout'))  # Wyloguj, jeśli użytkownik próbuje wejść do niewłaściwego modułu

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
    if 'user' not in session or session.get("module") != "warehouse":
        return redirect(url_for('logout'))  # Wyloguj, jeśli użytkownik próbuje wejść do niewłaściwego modułu

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
    if 'user' not in session or session.get("module") != "warehouse":
        return redirect(url_for('logout'))  # Wyloguj, jeśli użytkownik próbuje wejść do niewłaściwego modułu

    product = Product.query.get_or_404(product_id)
    db.session.delete(product)
    db.session.commit()
    return jsonify({"message": "Product deleted successfully!"})

# --------------------------
# Uruchomienie aplikacji
# --------------------------

if __name__ == "__main__":
    app.run(debug=True)
