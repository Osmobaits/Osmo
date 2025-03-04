from flask import Flask, request, render_template, redirect, url_for, session, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os
from functools import wraps
from flask_bcrypt import Bcrypt
from sqlalchemy.exc import SQLAlchemyError, OperationalError
import logging

# --- Inicjalizacja Aplikacji Flask ---
app = Flask(__name__, template_folder="templates")

# --- Konfiguracja Logowania ---
app.logger.setLevel(logging.INFO)
handler = logging.FileHandler('app.log')
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
app.logger.addHandler(handler)

# --- Konfiguracja Aplikacji ---
app.secret_key = os.environ.get('SECRET_KEY')
if not app.secret_key:
    import secrets
    app.secret_key = secrets.token_urlsafe(32)
    app.logger.warning("WARNING: SECRET_KEY not found in environment. Using randomly generated key. INSECURE!")

app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://magazyn_user:FH1mT4UHJvVrqmXXfQz6koc6FnVB3szQ@dpg-cuovb9ggph6c73dqpvc0-a/magazyn"  # Twoje URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# --- Modele ---
class Client(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    orders = db.relationship('Order', backref='client', lazy=True, cascade="all, delete-orphan")
    products = db.relationship('ClientProduct', backref='client', lazy=True, cascade="all, delete-orphan")
    username = db.Column(db.String(80), unique=True, nullable=False)  # Unikalna nazwa użytkownika
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False) #pole informujące czy klient jest adminem

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

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

class User(db.Model):  #  Model User dla administratora
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

# --- Funkcje Pomocnicze (Data Access - tymczasowo w app.py) ---

def has_active_order(client_id):
    try:
        return Order.query.filter_by(client_id=client_id, is_archived=False).first() is not None
    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"Error checking for active orders for client {client_id}: {e}")
        return False

def get_all_clients():
    try:
        return Client.query.all()
    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"Error getting all clients: {e}")
        raise

def get_active_orders():
    try:
        return Order.query.filter_by(is_archived=False).all()
    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"Error getting active orders: {e}")
        raise

def create_client(name, username, password):  # Dodaj username i password
    try:
        # Sprawdź, czy użytkownik o takiej nazwie już istnieje:
        existing_client = get_client_by_username(username)  # Użyj nowej funkcji
        if existing_client:
            raise ValueError(f"Użytkownik o nazwie '{username}' już istnieje.")

        new_client = Client(name=name, username=username)  # Dodaj username
        new_client.set_password(password)  # Ustaw hasło (haszowanie)
        db.session.add(new_client)
        db.session.commit()
        return new_client
    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"Error creating client: {e}")
        raise

def get_client_by_username(username):  # Nowa funkcja!
    try:
        return Client.query.filter_by(username=username).first()
    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"Error getting client by username: {e}")
        raise

def delete_client(client_id):
    try:
        client = Client.query.get_or_404(client_id)
        if client.is_admin:
            raise ValueError("Nie można usunąć konta administratora.")
        db.session.delete(client)
        db.session.commit()
    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"Error deleting client: {e}")
        raise

def get_client_by_id(client_id):
    try:
        return Client.query.get_or_404(client_id)
    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"Error getting client by ID: {e}")
        raise

def create_order(client_id, order_date):
    try:
        new_order = Order(order_date=order_date, client_id=client_id)
        db.session.add(new_order)
        db.session.commit()
        return new_order
    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"Error creating order: {e}")
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
        app.logger.error(f"Error adding products to order: {e}")
        raise

def get_order_by_id(order_id):
    try:
        order = Order.query.get_or_404(order_id)
        # Jawne sortowanie produktów po ID (rosnąco):
        order.products.sort(key=lambda p: p.id)
        return order
    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"Error getting order by ID: {e}")
        raise

def create_client_product(client_id, product_name):
    try:
        new_product = ClientProduct(name=product_name, client_id=client_id)
        db.session.add(new_product)
        db.session.commit()
        return new_product
    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"Error creating client product: {e}")
        raise

def delete_client_product(product_id):
    try:
        product = ClientProduct.query.get_or_404(product_id)
        db.session.delete(product)
        db.session.commit()
        return product.client_id
    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"Error deleting client product: {e}")
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
        app.logger.error(f"Error updating order product quantity: {e}")
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
        app.logger.error(f"Error deleting order product: {e}")
        raise

def update_shipment_date(order_id, shipment_date_str):
    try:
        order = Order.query.get_or_404(order_id)
        order.shipment_date = datetime.strptime(shipment_date_str, '%Y-%m-%d').date() if shipment_date_str else None
        db.session.commit()
        return order_id
    except (SQLAlchemyError, ValueError) as e:
        db.session.rollback()
        app.logger.error(f"Error updating shipment date: {e}")
        return None

def complete_order(order_id):
    try:
        order = Order.query.get_or_404(order_id)
        order.is_archived = True
        db.session.commit()
        return True
    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"Error completing order: {e}")
        return False

def update_invoice_number(order_id, invoice_number):
    try:
        order = Order.query.get_or_404(order_id)
        order.invoice_number = invoice_number
        db.session.commit()
        return order_id
    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"Error updating invoice number: {e}")
        return None

def delete_archived_order(order_id):
    try:
        order = Order.query.get_or_404(order_id)
        client_id = order.client_id
        app.logger.info(f"Deleting archived order with ID: {order_id}")
        db.session.delete(order)
        db.session.commit()
        app.logger.info(f"Archived order with ID: {order_id} deleted successfully (client ID: {client_id})")
        return client_id
    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"Error deleting archived order with ID {order_id}: {e}")
        raise

def create_user(username, password):
    try:
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        return new_user
    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"Error creating user: {e}")
        raise

def get_user_by_username(username):
    try:
        return User.query.filter_by(username=username).first()
    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"Error getting user by username: {e}")
        raise

def change_user_password(username, new_password):
    try:
        user = get_user_by_username(username)
        if user:
            user.set_password(new_password)
            db.session.commit()
            return True
        else:
            return False
    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"Error changing password for user {username}: {e}")
        raise

# --- Inicjalizacja Bazy Danych i Tworzenie Użytkownika ---
with app.app_context():
    try:
        db.create_all()
        app.logger.info("Database tables created successfully.")

        # Sprawdź, czy użytkownik admin już istnieje (na podstawie zmiennych środowiskowych)
        admin_username = os.environ.get('ADMIN_USERNAME')
        admin_password = os.environ.get('ADMIN_PASSWORD')

        if admin_username and admin_password:
            existing_user = get_user_by_username(admin_username)
            if not existing_user:
                create_user(admin_username, admin_password)
                app.logger.info(f"Admin user '{admin_username}' created.")
            else:
                app.logger.info(f"Admin user '{admin_username}' already exists.")
        else:
            app.logger.warning("ADMIN_USERNAME or ADMIN_PASSWORD environment variables not set.  Admin user not created.")

    except OperationalError as e:
        app.logger.error(f"Database initialization error: {e}")
        print(f"Database initialization error: {e}")  # Wypisz do konsoli w razie problemów z loggerem na początku


# --- Dekorator Autoryzacji ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session and "client_user" not in session:
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function

# --- Endpointy ---

@app.route('/login', methods=['GET'])
def login_page():
    return render_template('index1.html')

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = get_user_by_username(data.get("username"))  # Pobierz użytkownika z bazy

    if user and user.check_password(data.get("password")):  # Sprawdź hasło
        session["user"] = user.username
        return jsonify({"redirect": url_for("orders"), "message": "Login successful"})

    return jsonify({"message": "Invalid credentials"}), 401

@app.route('/logout', methods=['GET'])
def logout():
    session.clear()
    return redirect(url_for('login_page'))

@app.route('/')
@login_required
def home():
    return redirect(url_for("orders"))

@app.route('/orders')
@login_required
def orders():
    clients = get_all_clients()
    active_orders = get_active_orders()
    client_has_active_order = {}
    for client in clients:
        client_has_active_order[client.id] = has_active_order(client.id)

    # Pobierz ADMIN_USERNAME i przekaż do szablonu:
    admin_username = os.environ.get("ADMIN_USERNAME")
    #Pobieranie zamówień do faktury
    orders_to_invoice = Order.query.filter_by(is_archived=True, invoice_number=None).all()
    return render_template('index1.html', clients=clients, active_orders=active_orders,
                           client_has_active_order=client_has_active_order, admin_username=admin_username, orders_to_invoice=orders_to_invoice) #przekazujemy zmienna

@app.route('/add_client', methods=['POST'])
@login_required
def add_client():
    name = request.form.get('name')
    username = request.form.get('username')  # Dodaj pobieranie username
    password = request.form.get('password')  # Dodaj pobieranie password
    confirm_password = request.form.get('confirm_password')

    if not all([name, username, password, confirm_password]):
        flash("Wszystkie pola są wymagane.", "error")
        return redirect(url_for('orders'))

    if password != confirm_password:
        flash("Hasła nie są identyczne.", "error")
        return redirect(url_for('orders'))

    try:
        create_client(name, username, password)  # Użyj zmodyfikowanej funkcji
        flash(f"Klient '{name}' został dodany.", "success")
    except ValueError as e:  # Obsłuż błąd unikalności username
        flash(str(e), "error")
    except Exception as e:
        app.logger.error(f"Error adding client: {e}")
        flash("Błąd podczas dodawania klienta.", "error")
    return redirect(url_for('orders'))

@app.route('/delete_client/<int:client_id>', methods=['POST'])
@login_required
def delete_client(client_id):
    try:
        delete_client(client_id)
        flash("Klient został usunięty.", "success")
    except ValueError as e:
        flash(str(e), "error") # wyświetl błąd
    except Exception as e:
        app.logger.error(f"Error deleting client: {e}")
        flash("Błąd podczas usuwania klienta.", "error")
    return redirect(url_for('orders'))

@app.route('/client/<int:client_id>')
@login_required
def client_details(client_id):
    try:
        app.logger.info(f"Entering client_details page for client ID: {client_id}")
        client = get_client_by_id(client_id)
        archived_orders = Order.query.filter_by(client_id=client.id, is_archived=True).order_by(Order.order_date.desc()).all()
        return render_template('client_details.html', client=client, archived_orders=archived_orders)
    except Exception as e:
        app.logger.error(f"Error getting client details: {e}")
        return render_template("error.html", error="Błąd podczas pobierania szczegółów klienta.")

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
        app.logger.error(f"Error adding order: {e}")
        return render_template("error.html", error="Błąd podczas dodawania zamówienia.")

@app.route('/order/<int:order_id>')
@login_required
def order_details(order_id):
    try:
        order = get_order_by_id(order_id)
        return render_template('order_details.html', order=order)
    except Exception as e:
        app.logger.error(f"Error getting order details: {e}")
        return render_template("error.html", error="Błąd podczas pobierania szczegółów zamówienia.")

@app.route('/add_product/<int:client_id>', methods=['POST'])
@login_required
def add_product(client_id):
    try:
        product_name = request.form.get('product_name')
        if product_name:
            create_client_product(client_id, product_name)
        return redirect(url_for('client_details', client_id=client_id))
    except Exception as e:
        app.logger.error(f"Error adding product: {e}")
        return render_template("error.html", error="Błąd podczas dodawania produktu.")

@app.route('/delete_client_product/<int:product_id>', methods=['POST'])
@login_required
def delete_client_product(product_id):
    try:
        client_id = delete_client_product(product_id)
        return redirect(url_for('client_details', client_id=client_id))
    except Exception as e:
        app.logger.error(f"Error deleting client product: {e}")
        return render_template("error.html", error="Błąd podczas usuwania produktu.")

@app.route('/update_product_quantity/<int:product_id>', methods=['POST'])
@login_required
def update_product_quantity(product_id):
    data = request.get_json()
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
        app.logger.error(f"Error deleting order product: {e}")
        return render_template("error.html", error="Błąd podczas usuwania produktu z zamówienia.")

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
    order = Order.query.get_or_404(order_id)
    order.is_archived = True
    db.session.commit()
    return jsonify({'success': True})

@app.route('/update_invoice_number/<int:order_id>', methods=['POST'])
@login_required
def update_invoice_number(order_id):
    invoice_number = request.form.get('invoice_number')
    order_id = update_invoice_number(order_id, invoice_number)
    if order_id is None:
        return jsonify({'success': False, 'error': 'Could not update invoice number'}), 500
    return redirect(url_for('order_details', order_id=order_id))

@app.route('/delete_archived_order/<int:order_id>', methods=['POST'])
@login_required
def delete_archived_order_route(order_id):  # Zmieniona nazwa endpointu
    try:
        app.logger.info(f"Received request to delete archived order with ID: {order_id}")
        client_id = delete_archived_order(order_id)
        app.logger.info(f"Redirecting to client details page (client ID: {client_id})")
        return redirect(url_for('client_details', client_id=client_id))
    except Exception as e:
        app.logger.error(f"Error deleting archived order: {e}")
        return render_template("error.html", error="Błąd podczas usuwania zarchiwizowanego zamówienia.")

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password == confirm_password:
            try:
                success = change_user_password(session['user'], new_password)
                if success:
                    flash("Hasło zostało zmienione.", "success")
                    return redirect(url_for('orders'))
                else:
                    flash("Nie udało się zmienić hasła.", "error")
            except Exception as e:
                app.logger.error(f"Error changing password: {e}")
                flash("Wystąpił błąd podczas zmiany hasła.", "error")
        else:
            flash("Hasła nie są identyczne.", "error")

    return render_template('change_password.html')

@app.route('/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    # Sprawdź, czy zalogowany użytkownik to admin (tymczasowo - później to zmienimy)
    if session.get('user') != os.environ.get("ADMIN_USERNAME"):
        flash("Nie masz uprawnień do dodawania użytkowników.", "error")
        return redirect(url_for('orders'))  # Przekieruj, jeśli nie admin

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not username or not password or not confirm_password:
            flash("Wszystkie pola są wymagane.", "error")
            return render_template('add_user.html')

        if password != confirm_password:
            flash("Hasła nie są identyczne.", "error")
            return render_template('add_user.html')

        try:
            existing_user = get_user_by_username(username)
            if existing_user:
                flash("Użytkownik o podanej nazwie już istnieje.", "error")
                return render_template('add_user.html')

            create_user(username, password)
            flash(f"Użytkownik '{username}' został dodany.", "success")
            return redirect(url_for('orders')) #lub innej strony np lista uzytkowników
        except Exception as e:
            app.logger.error(f"Error adding user: {e}")
            flash("Wystąpił błąd podczas dodawania użytkownika.", "error")

    return render_template('add_user.html')

# Endpoint logowania dla klientów
@app.route('/client_login', methods=['GET', 'POST'])
def client_login():
    if request.method == 'POST':
        data = request.json #pobieramy dane
        username = data.get("username")
        password = data.get("password")

        client = get_client_by_username(username) #pobieramy klienta

        if client and client.check_password(password): #sprawdzamy haslo
            session["client_user"] = client.username #zapis do sesji
            #tutaj przekierowanie
            return jsonify({"redirect": url_for("client_dashboard"), "message": "Login successful"}) #Przekierowanie do panelu klienta

        return jsonify({"message": "Invalid credentials"}), 401

    return render_template('client_login.html') # Stwórz ten szablon!

@app.route('/client_logout')
def client_logout():
    session.pop('client_user', None)  # Usuń 'client_user' z sesji
    return redirect(url_for('home'))  # Przekieruj na stronę główną (lub inną)

@app.route('/client_dashboard')
@login_required
def client_dashboard():
    # Pobierz dane klienta (na podstawie sesji)
    client = get_client_by_username(session['client_user'])
    if client is None: #zabezpieczenie
        return redirect(url_for("client_login"))

    # Możesz tutaj pobrać inne dane, np. historię zamówień klienta
    # client_orders = ...

    return render_template('client_dashboard.html', client=client)

@app.route('/client_new_order', methods=['GET', 'POST'])
@login_required  # Upewnij się, że tylko zalogowani klienci mogą składać zamówienia
def client_new_order():
  client = get_client_by_username(session["client_user"])

  if client is None:
      return redirect(url_for("client_login"))

  if request.method == 'POST':
      order_date_str = request.form.get('order_date')
      order_date = datetime.strptime(order_date_str, '%Y-%m-%d').date() if order_date_str else None

      try:
          new_order = create_order(client.id, order_date)
          # Pobierz wszystkie produkty klienta
          for product in client.products:
              quantity_key = f"product_{product.id}"
              quantity = request.form.get(quantity_key, type=int, default=0)  # Pobierz ilość, domyślnie 0

              if quantity > 0:
                  order_product = OrderProduct(
                      name=product.name,
                      quantity_ordered=quantity,
                      order_id=new_order.id
                  )
                  db.session.add(order_product)
          db.session.commit() #zapis do bazy
          flash('Zamówienie zostało złożone!', 'success')
          return redirect(url_for('client_dashboard'))

      except Exception as e:
          app.logger.error(f"Error create order for client: {e}")
          flash("Błąd przy składaniu zamówienia", "error")
          db.session.rollback()

  return render_template('client_new_order.html', client=client)

@app.route('/client_products/<int:client_id>')
@login_required
def client_products(client_id):
  try:
      client = get_client_by_id(client_id) #pobieramy klienta po id
      products = [{"id": product.id, "name": product.name} for product in client.products] #tworzymy listę słowników
      return jsonify(products) #zwracamy json
  except Exception as e:
      app.logger.error(f"Error client product: {e}")
      return jsonify({'success': False, 'error': str(e)}), 400

@app.errorhandler(Exception)
def handle_exception(e):
    app.logger.error(f"An error occurred: {e}")
    return render_template('error.html', error=str(e)), 500

if __name__ == "__main__":
    app.run(debug=True)
