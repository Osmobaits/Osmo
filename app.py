from flask import Flask, request, render_template, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os
from functools import wraps
from flask_bcrypt import Bcrypt
from sqlalchemy.exc import SQLAlchemyError # Importuj SQLAlchemyError

# Inicjalizacja aplikacji Flask
app = Flask(__name__, template_folder="templates")

# ... (reszta konfiguracji app - secret_key, database URI, itp.) ...
app.secret_key = os.environ.get('SECRET_KEY')
if not app.secret_key:
    import secrets
    app.secret_key = secrets.token_urlsafe(32)
    print("WARNING: SECRET_KEY not found in environment.  Using a randomly generated key.  This is INSECURE for production!")

app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://magazyn_user:FH1mT4UHJvVrqmXXfQz6koc6FnVB3szQ@dpg-cuovb9ggph6c73dqpvc0-a/magazyn"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# ... (Modele: Client, Order, ClientProduct, OrderProduct) ...
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
    wykulane = db.Column(db.Integer, nullable=False, default=0)
    quantity_packed = db.Column(db.Integer, nullable=False, default=0)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)

# ... (Tworzenie bazy danych) ...
with app.app_context():
    db.create_all()

# ... (Logowanie - BEZ ZMIAN, ale pamiętaj o przeniesieniu do bazy!) ...
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "magazyn12"
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET'])
def login_page():
    return render_template('index1.html')

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = None
    if data.get("username") == ADMIN_USERNAME:
        user = {"username": ADMIN_USERNAME, "password": bcrypt.generate_password_hash(ADMIN_PASSWORD).decode('utf-8')}

    if user and bcrypt.check_password_hash(user["password"], data.get("password")):
        session["user"] = user["username"]
        return jsonify({"redirect": url_for("orders"), "message": "Login successful"})

    return jsonify({"message": "Invalid credentials"}), 401

@app.route('/logout', methods=['GET'])
def logout():
    session.clear()
    return redirect(url_for('login_page'))
# ... (Funkcje data access - wklejamy je tutaj) ...
def has_active_order(client_id):
    try:
        return Order.query.filter_by(client_id=client_id, is_archived=False).first() is not None
    except SQLAlchemyError as e:
        db.session.rollback()
        print(f"Error checking for active orders for client {client_id}: {e}")  # Proste logowanie do konsoli
        # W produkcyjnej aplikacji, użyj app.logger zamiast print!
        return False # lub raise, zaleznie od potrzeb

def get_all_clients():
  try:
    return Client.query.all()
  except SQLAlchemyError as e:
        db.session.rollback()
        print(f"Error get all clients")
        raise

def get_active_orders():
    try:
      return Order.query.filter_by(is_archived=False).all()
    except SQLAlchemyError as e:
        db.session.rollback()
        print(f"Error get active orders")
        raise

def create_client(name):
    try:
        new_client = Client(name=name)
        db.session.add(new_client)
        db.session.commit()
        return new_client
    except SQLAlchemyError as e:
        db.session.rollback()
      # Loguj błąd
        raise

def delete_client(client_id):
  try:
    client = Client.query.get_or_404(client_id)
    db.session.delete(client)
    db.session.commit()
  except SQLAlchemyError as e:
        db.session.rollback()
    # Loguj błąd
        raise

def get_client_by_id(client_id):
   try:
      return Client.query.get_or_404(client_id)
   except SQLAlchemyError as e:
        db.session.rollback()
        # Loguj błąd
        raise

def create_order(client_id, order_date):
  try:
    new_order = Order(order_date=order_date, client_id=client_id)
    db.session.add(new_order)
    db.session.commit()
    return new_order
  except SQLAlchemyError as e:
        db.session.rollback()
    # Loguj błąd
        raise


def add_products_to_order(order, client):
  try:
    for client_product in client.products:
        order_product = OrderProduct(
            name=client_product.name,
            quantity_ordered=0,
            quantity_packed=0,
            wykulane=0,
            order_id=order.id
        )
        db.session.add(order_product)
    db.session.commit()
  except SQLAlchemyError as e:
        db.session.rollback()
    # Loguj błąd
        raise

def get_order_by_id(order_id):
  try:
        return Order.query.get_or_404(order_id)
  except SQLAlchemyError as e:
      db.session.rollback()
      raise

def create_client_product(client_id, product_name):
  try:
    new_product = ClientProduct(name=product_name, client_id=client_id)
    db.session.add(new_product)
    db.session.commit()
    return new_product
  except SQLAlchemyError as e:
    db.session.rollback()
    # Loguj błąd
    raise

def delete_client_product(product_id):
    try:
        product = ClientProduct.query.get_or_404(product_id)
        db.session.delete(product)
        db.session.commit()
        return product.client_id # Zwróć client_id
    except SQLAlchemyError as e:
        db.session.rollback()
        # Loguj błąd
        raise

def update_order_product_quantity(product_id, quantity_ordered=None, quantity_packed=None, wykulaned=None):
    try:
        product = OrderProduct.query.get_or_404(product_id)
        if quantity_ordered is not None:
            product.quantity_ordered = int(quantity_ordered)
        if quantity_packed is not None:
            product.quantity_packed = int(quantity_packed)
        if wykulaned is not None:
            product.wykulane = int(wykulaned)
        db.session.commit()
        return True
    except (SQLAlchemyError, ValueError, TypeError) as e:
        db.session.rollback()
          # Loguj błąd
        return False

def delete_order_product(product_id):
    try:
        product = OrderProduct.query.get_or_404(product_id)
        order_id = product.order_id
        db.session.delete(product)
        db.session.commit()
        return order_id
    except SQLAlchemyError as e:
        db.session.rollback()
        # Loguj błąd
        raise

def update_shipment_date(order_id, shipment_date_str):
  try:
      order = Order.query.get_or_404(order_id)
      order.shipment_date = datetime.strptime(shipment_date_str, '%Y-%m-%d').date() if shipment_date_str else None
      db.session.commit()
      return order_id
  except (SQLAlchemyError, ValueError) as e:
      db.session.rollback()
      # Loguj błąd (dodaj app.logger)
      return None

def complete_order(order_id):
    try:
        order = Order.query.get_or_404(order_id)
        order.is_archived = True
        db.session.commit()
        return True
    except SQLAlchemyError as e:
        db.session.rollback()
          # Loguj błąd
        return False

def update_invoice_number(order_id, invoice_number):
  try:
      order = Order.query.get_or_404(order_id)
      order.invoice_number = invoice_number
      db.session.commit()
      return order_id
  except SQLAlchemyError as e:
      db.session.rollback()
      # Loguj błąd
      return None

def delete_archived_order(order_id):
    try:
        order = Order.query.get_or_404(order_id)
        client_id = order.client_id
        db.session.delete(order)
        db.session.commit()
        return client_id
    except SQLAlchemyError as e:
      db.session.rollback()
      # Loguj błąd
      raise

# ... (Endpointy - używają funkcji data access) ...
@app.route('/')
@login_required
def home():
    return redirect(url_for("orders"))

@app.route('/orders')
@login_required
def orders():
    clients = get_all_clients()  # Użyj funkcji z data_access
    active_orders = get_active_orders()

    # Tworzymy słownik, który mapuje ID klienta na informację, czy ma aktywne zamówienie.
    client_has_active_order = {}
    for client in clients:
        client_has_active_order[client.id] = has_active_order(client.id)

    return render_template('index1.html', clients=clients, active_orders=active_orders, client_has_active_order=client_has_active_order)

@app.route('/add_client', methods=['POST'])
@login_required
def add_client():
    name = request.form.get('name')
    if name:
      try:
        create_client(name)
      except Exception as e:
        print(f"Error add client: {e}") #proste logowanie do konsoli, produkcyjnie uzyj app.logger
        return render_template("error.html", error="Błąd podczas dodawania klienta") #musisz stworzyć error.html

    return redirect(url_for('orders'))

@app.route('/delete_client/<int:client_id>', methods=['POST'])
@login_required
def delete_client(client_id):
  try:
    delete_client(client_id)
  except Exception as e:
      print(f"Error delete client: {e}")
      return render_template("error.html", error="Błąd podczas usuwania klienta")

  return redirect(url_for('orders'))

@app.route('/client/<int:client_id>')
@login_required
def client_details(client_id):
  try:
    client = get_client_by_id(client_id)
    archived_orders = Order.query.filter_by(client_id=client.id, is_archived=True).order_by(Order.order_date.desc()).all()
    return render_template('client_details.html', client=client, archived_orders=archived_orders)
  except Exception as e:
      print(f"Error client details: {e}")
      return render_template("error.html", error="Błąd podczas pobierania szczegółów klienta")

@app.route('/add_order/<int:client_id>', methods=['POST'])
@login_required
def add_order(client_id):
  try:
    order_date_str = request.form.get('order_date')
    order_date = datetime.strptime(order_date_str, '%Y-%m-%d').date() if order_date_str else None

    new_order = create_order(client_id, order_date)
    client = get_client_by_id(client_id)
    add_products_to_order(new_order, client)
    return redirect(url_for('order_details', order_id=new_order.id))
  except Exception as e:
      print(f"Error add order: {e}") #proste logowanie
      return render_template("error.html", error="Bład podczas dodawania zamówienia")

@app.route('/order/<int:order_id>')
@login_required
def order_details(order_id):
    try:
      order = get_order_by_id(order_id)
      return render_template('order_details.html', order=order)
    except Exception as e:
        print(f"Error order details: {e}")
        return render_template("error.html", error = "Błąd podczas pobierania szczegółów zamówienia")

@app.route('/add_product/<int:client_id>', methods=['POST'])
@login_required
def add_product(client_id):
  try:
    product_name = request.form.get('product_name')
    if product_name:
        create_client_product(client_id, product_name)

    return redirect(url_for('client_details', client_id=client_id))
  except Exception as e:
      print(f"Error add product: {e}")
      return render_template("error.html", error="Błąd podczas dodawania produktu")

@app.route('/delete_client_product/<int:product_id>', methods=['POST'])
@login_required
def delete_client_product(product_id):
    try:
        client_id = delete_client_product(product_id)
        return redirect(url_for('client_details', client_id=client_id))
    except Exception as e:
        print(f"Error delete client product: {e}")
        return render_template("error.html", error="Błąd podczas usuwania produktu")

@app.route('/update_product_quantity/<int:product_id>', methods=['POST'])
@login_required
def update_product_quantity(product_id):
    data = request.get_json()
    # Użyj jednej funkcji do aktualizacji wszystkich pól
    success = update_order_product_quantity(
      product_id,
      data.get('quantity_ordered'),
      data.get('quantity_packed'),
      data.get('wykulane')
    )
    return jsonify({'success': success})

@app.route('/delete_order_product/<int:product_id>', methods=['POST'])
@login_required
def delete_order_product(product_id):
  try:
    order_id = delete_order_product(product_id)
    return redirect(url_for('order_details', order_id=order_id))
  except Exception as e:
      print(f"Error delete order product: {e}")
      return render_template("error.html", error="Błąd podczas usuwania produktu z zamówienia")
@app.route('/update_shipment_date/<int:order_id>', methods=['POST'])
@login_required
def update_shipment_date(order_id):
    shipment_date_str = request.form.get('shipment_date')
    order_id = update_shipment_date(order_id, shipment_date_str)
    if order_id is None:
        return jsonify({'success': False, 'error': 'Could not update shipment date'}), 500
    return redirect(url_for('order_details', order_id=order_id))

@app.route('/complete_order/<int:order_id>', methods=['POST'])
@login_required
def complete_order(order_id):
  try:
    complete_order(order_id)
    return jsonify({'success': True})
  except Exception as e:
      print(f"Error complete order: {e}")
      return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/update_invoice_number/<int:order_id>', methods=['POST'])
@login_required
def update_invoice_number(order_id):
    invoice_number = request.form.get('invoice_number')
    order_id = update_invoice_number(order_id, invoice_number)
    if order_id is None:
      return  jsonify({'success': False, 'error': 'Could not update invoice number'}), 500
    return redirect(url_for('order_details', order_id=order_id))

@app.route('/delete_archived_order/<int:order_id>', methods=['POST'])
@login_required
def delete_archived_order(order_id):
  try:
    client_id = delete_archived_order(order_id)
    return redirect(url_for('client_details', client_id=client_id))
  except Exception as e:
      print(f"Error delete archived order: {e}")
      return render_template("error.html", error="Błąd podczas usuwania zarchiwizowanego zamówienia")
# ... (inne endpointy) ...

if __name__ == "__main__":
    app.run(debug=True)
