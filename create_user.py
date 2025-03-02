# create_user.py
from app import app, db  # Importuj app i db z app.py
from models import User  # Importuj model User (zakładając, że masz plik models.py)
#from app import User #jeśli nie masz pliku models, tylko wszystko w app.py

def create_admin_user():
    with app.app_context():
        # Sprawdź, czy użytkownik już istnieje (opcjonalnie)
        existing_user = User.query.filter_by(username="admin").first()
        if not existing_user:
            # Utwórz użytkownika "admin" z *tymczasowym* hasłem.
            # ZMIEŃ TO HASŁO po pierwszym uruchomieniu!
            create_user("admin", "tymczasowe_haslo123")
            print("Admin user created.")
        else:
            print("Admin user already exists.")

if __name__ == "__main__":
    create_admin_user()
