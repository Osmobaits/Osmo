from flask import Flask, request, render_template, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os

# Inicjalizacja aplikacji Flask
app = Flask(__name__)
app.secret_key = 'tajny_klucz'  # Klucz do szyfrowania sesji

# Konfiguracja bazy danych
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "kontrahenci.db")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + DB_PATH
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Inicjalizacja SQLAlchemy
db = SQLAlchemy(app)

# Model produktu klienta
class ClientProduct(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    client_id = db.Column(db.Integer, db.ForeignKey('client.id'), nullable=False)  # Przypisanie do klienta

# Model produktu w zamówieniu
class OrderProduct(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    quantity_ordered = db.Column(db.Integer, nullable=False, default=0)  # Domyślnie 0
    quantity_packed = db.Column(db.Integer, nullable=False, default=0)   # Domyślnie 0
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)  # Przypisanie do zamówienia

# Model zamówienia
class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_date = db.Column(db.Date, nullable=True)  # Data przyjęcia zamówienia
    shipment_date = db.Column(db.Date, nullable=True)  # Data wysyłki (może być pusta)
    is_archived = db.Column(db.Boolean, default=False)  # Czy zamówienie jest archiwalne
    invoice_number = db.Column(db.String(50), nullable=True)  # Numer faktury (może być pusty)
    client_id = db.Column(db.Integer, db.ForeignKey('client.id'), nullable=False)
    products = db.relationship('OrderProduct', backref='order', lazy=True, cascade="all, delete-orphan")  # Produkty w zamówieniu

# Model klienta
class Client(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    orders = db.relationship('Order', backref='client', lazy=True, cascade="all, delete-orphan")
    products = db.relationship('ClientProduct', backref='client', lazy=True, cascade="all, delete-orphan")  # Produkty klienta

# Tworzenie bazy danych
with app.app_context():
    db.create_all()

# Strona główna (logowanie)
@app.route('/', methods=['GET', 'POST'])
def home():
    if 'user' in session:
        # Sprawdź, do którego modułu użytkownik jest zalogowany
        if session.get('module') == 'orders':
            clients = Client.query.all()
            active_orders = Order.query.filter_by(is_archived=False).all()
            return render_template('index1.html', username=session['user'], clients=clients, active_orders=active_orders)
        elif session.get('module') == 'warehouse':
            return redirect(url_for('warehouse_home'))  # Przekieruj do modułu magazynu

    message = ""
    if request.method == 'POST':
        user_login = request.form.get('login')
        user_password = request.form.get('password')
        module = request.form.get('module')  # Pobierz wybrany moduł

        if user_login == "admin" and user_password == "magazyn12":
            session['user'] = user_login
            session['module'] = module  # Zapisz wybrany moduł w sesji
            if module == 'orders':
                return redirect(url_for('home'))
            elif module == 'warehouse':
                return redirect(url_for('warehouse_home'))  # Przekieruj do modułu magazynu
        else:
            message = "Błędny login lub hasło. Spróbuj ponownie."

    return render_template('index1.html', message=message)

# Wylogowanie
@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('module', None)  # Usuń również informację o module
    return redirect(url_for('home'))

# Moduł magazynu
@app.route('/warehouse')
def warehouse_home():
    if 'user' not in session or session.get('module') != 'warehouse':
        return redirect(url_for('home'))  # Przekieruj do logowania, jeśli użytkownik nie jest zalogowany do magazynu

    # Renderuj istniejący index.html dla modułu magazynu
    return render_template('index.html', logged_in=True)

# Reszta endpointów (np. dodawanie klienta, zamówień itp.) pozostaje bez zmian
# ...

# Uruchomienie aplikacji
if __name__ == "__main__":
    app.run(debug=True)
