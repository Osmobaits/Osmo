# app.py
from flask import Flask, request, render_template, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os
from functools import wraps
from flask_bcrypt import Bcrypt  # Import bcrypt

# Inicjalizacja aplikacji Flask
app = Flask(__name__, template_folder="templates")

# Bezpieczny Secret Key (zmienna środowiskowa)
app.secret_key = os.environ.get('SECRET_KEY')
if not app.secret_key:  # Dodatkowe zabezpieczenie, jesli nie ma zmiennej srodowiskowej
    import secrets
    app.secret_key = secrets.token_urlsafe(32)
    print("WARNING: SECRET_KEY not found in environment. Using a randomly generated key.  This is INSECURE for production!")

# Konfiguracja bazy danych (PostgreSQL z Render)
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://magazyn_user:FH1mT4UHJvVrqmXXfQz6koc6FnVB3szQ@dpg-cuovb9ggph6c73dqpvc0-a/magazyn"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Inicjalizacja SQLAlchemy i bcrypt
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)


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
# Tworzenie bazy danych
# --------------------------

with app.app_context():
    db.create_all()

# --------------------------
# Wspólny system logowania (z haszowaniem haseł)
# --------------------------

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "magazyn12"  # To *nadal* powinno być zmienione i zahaszowane w bazie!

# Dekorator autoryzacji (dla modułu zamówień)
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function

# Endpoint do wyświetlenia strony logowania (GET)
@app.route('/login', methods=['GET'])
def login_page():
    return render_template('index1.html')  # Użyj index1.html (bez sekcji logowania dla modułu)

# Endpoint do obsługi logowania (POST)
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    # To *tymczasowe* rozwiązanie - docelowo pobieraj użytkownika z bazy!
    user = None
    if data.get("username") == ADMIN_USERNAME:
        user = {"username": ADMIN_USERNAME, "password": bcrypt.generate_password_hash(ADMIN_PASSWORD).decode('utf-8')}

    if user and bcrypt.check_password_hash(user["password"], data.get("password")):
        session["user"] = user["username"]
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
@login_required #dodajemy dekorator
def home():
    return redirect(url_for("orders"))  # Przekieruj do zamówień

@app.route('/orders')
@login_required #dodajemy dekorator
def orders():
    clients = Client.query.all()
    active_orders = Order.query.filter_by(is_archived=False).all()
    return render_template('index1.html', clients=clients, active_orders=active_orders)

@app.route('/add_client', methods=['POST'])
@login_required #dodajemy dekorator
def add_client():
    name = request.form.get('name')
    if name:
        new_client = Client(name=name)
        db.session.add(new_client)
        db.session.commit()

    return redirect(url_for('orders'))  # Przekieruj z powrotem do listy zamówień

@app.route('/delete_client/<int:client_id>', methods=['POST'])
@login_required #dodajemy dekorator
def delete_client(client_id):
    client = Client.query.get_or_404(client_id)
    db.session.delete(client)
    db.session.commit()

    return redirect(url_for('orders'))  # Przekieruj z powrotem do listy zamówień

@app.route('/client/<int:client_id>')
@login_required #dodajemy dekorator
def client_details(client_id):
    client = Client.query.get_or_404(client_id)
    archived_orders = Order.query.filter_by(client_id=client.id, is_archived=True).order_by(Order.order_date.desc()).all()
    return render_template('client_details.html', client=client, archived_orders=archived_orders)

@app.route('/add_order/<int:client_id>', methods=['POST'])
@login_required #dodajemy dekorator
def add_order(client_id):
    order_date_str = request.form.get('order_date')
    order_date = datetime.strptime(order_date_str, '%Y-%m-%d').date() if order_date_str else None

    new_order = Order(
        order_date=order_date,
        client_id=client_id
    )
    db.session.add(new_order)
    db.session.commit()  # Dodaj i zatwierdź zamówienie *przed* dodaniem produktów

    client = Client.query.get_or_404(client_id)
    for client_product in client.products:
        order_product = OrderProduct(
            name=client_product.name,
            quantity_ordered=0,
            quantity_packed=0,
            wykulane = 0,
            order_id=new_order.id
        )
        db.session.add(order_product)
    db.session.commit() #Zatwierdz po dodaniu wszystkich produktów

    return redirect(url_for('order_details', order_id=new_order.id))

@app.route('/order/<int:order_id>')
@login_required #dodajemy dekorator
def order_details(order_id):
    order = Order.query.get_or_404(order_id)
    return render_template('order_details.html', order=order)

@app.route('/add_product/<int:client_id>', methods=['POST'])
@login_required #dodajemy dekorator
def add_product(client_id):
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
@login_required #dodajemy dekorator
def delete_client_product(product_id):
    product = ClientProduct.query.get_or_404(product_id)
    client_id = product.client_id
    db.session.delete(product)
    db.session.commit()

    return redirect(url_for('client_details', client_id=client_id))

@app.route('/update_product_quantity/<int:product_id>', methods=['POST'])
@login_required #dodajemy dekorator
def update_product_quantity(product_id):
    product = OrderProduct.query.get_or_404(product_id)
    data = request.get_json()

    if 'quantity_ordered' in data:
        product.quantity_ordered = int(data['quantity_ordered'])
    if 'quantity_packed' in data:
        product.quantity_packed = int(data['quantity_packed'])
    if 'wykulane' in data:
        product.wykulane = int(data['wykulane'])

    db.session.commit()
    return jsonify({'success': True})

@app.route('/delete_order_product/<int:product_id>', methods=['POST'])
@login_required #dodajemy dekorator
def delete_order_product(product_id):
    product = OrderProduct.query.get_or_404(product_id)
    order_id = product.order_id
    db.session.delete(product)
    db.session.commit()

    return redirect(url_for('order_details', order_id=order_id))

@app.route('/update_shipment_date/<int:order_id>', methods=['POST'])
@login_required #dodajemy dekorator
def update_shipment_date(order_id):
    order = Order.query.get_or_404(order_id)
    shipment_date_str = request.form.get('shipment_date')

    order.shipment_date = datetime.strptime(shipment_date_str, '%Y-%m-%d').date() if shipment_date_str else None
    db.session.commit()

    return redirect(url_for('order_details', order_id=order_id))

@app.route('/complete_order/<int:order_id>', methods=['POST'])
@login_required #dodajemy dekorator
def complete_order(order_id):
    order = Order.query.get_or_404(order_id)
    order.is_archived = True
    db.session.commit()

    return jsonify({'success': True})

@app.route('/update_invoice_number/<int:order_id>', methods=['POST'])
@login_required #dodajemy dekorator
def update_invoice_number(order_id):

    order = Order.query.get_or_404(order_id)
    invoice_number = request.form.get('invoice_number')

    order.invoice_number = invoice_number
    db.session.commit()

    return redirect(url_for('order_details', order_id=order_id))

@app.route('/delete_archived_order/<int:order_id>', methods=['POST'])
@login_required #dodajemy dekorator
def delete_archived_order(order_id):

    order = Order.query.get_or_404(order_id)
    client_id = order.client_id
    db.session.delete(order)
    db.session.commit()

    return redirect(url_for('client_details', client_id=client_id))


# --------------------------
# Uruchomienie aplikacji
# --------------------------

if __name__ == "__main__":
    app.run(debug=True)
