from app import db, app

# Create the database within the application context
with app.app_context():
    db.create_all()
    print("✅ Database created successfully!")
