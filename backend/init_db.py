"""
Database initialization and re-seed runner.
"""

from app.database import Base, engine
import app.models
from seed_data import seed_database

def init_db(reset: bool = False):
    if reset:
        print("Dropping all existing database tables...")
        Base.metadata.drop_all(bind=engine)
    print("Creating database schema...")
    Base.metadata.create_all(bind=engine)
    print("Seeding database...")
    seed_database()
    print("Database initialization complete.")

if __name__ == "__main__":
    import sys
    should_reset = "--reset" in sys.argv
    init_db(reset=should_reset)
