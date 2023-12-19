import os

# Set environment variable for SQLAlchemy 2.0 warnings
#os.environ['SQLALCHEMY_WARN_20'] = '1'

from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, ForeignKey, Boolean, CheckConstraint
from sqlalchemy.orm import sessionmaker,declarative_base
from sqlalchemy_utils import database_exists,create_database
import json
import hashlib
from passlib.hash import bcrypt_sha256
import argparse
import csv
import datetime

Base = declarative_base()


def parse_args():
    parser = argparse.ArgumentParser(description="Update CTFd configuration and/or generate admin token.")
    parser.add_argument("--config_csv", help="Path to the configuration CSV file.", default=None)
    parser.add_argument("--admin_token", help="Generate admin token for a given username", default=None)
    return parser.parse_args()

class Token(Base):
    __tablename__ = 'tokens'
    id = Column(Integer, primary_key=True)
    type = Column(String(32))
    user_id = Column(Integer, ForeignKey('users.id'))
    created = Column(DateTime)
    expiration = Column(DateTime)
    value = Column(String(128), unique=True)
    description = Column(Text)

class Awards(Base):
    __tablename__ = 'awards'
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer)
    team_id = Column(Integer)
    name = Column(String(80))
    description = Column(Text)
    date = Column(DateTime)
    value = Column(Integer)
    category = Column(String(80))
    icon = Column(Text)
    requirements = Column(Text, CheckConstraint('json_valid(requirements)'))
    type = Column(String(80), default='standard')

class Challenges(Base):
    __tablename__ = 'challenges'
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(80))
    description = Column(Text)
    max_attempts = Column(Integer)
    value = Column(Integer)
    category = Column(String(80))
    type = Column(String(80))
    state = Column(String(80), nullable=False)
    requirements = Column(Text, CheckConstraint('json_valid(requirements)'))

class Config(Base):
    __tablename__ = 'config'
    id = Column(Integer, primary_key=True, autoincrement=True)
    key = Column(String(128), nullable=False)
    value = Column(Text, nullable=False)

class DynamicChallenge(Base):
    __tablename__ = 'dynamic_challenge'
    id = Column(Integer, primary_key=True)
    initial = Column(Integer)
    minimum = Column(Integer)
    decay = Column(Integer)

class Files(Base):
    __tablename__ = 'files'
    id = Column(Integer, primary_key=True, autoincrement=True)
    type = Column(String(80))
    location = Column(Text)
    challenge_id = Column(Integer)
    page_id = Column(Integer)

class Flags(Base):
    __tablename__ = 'flags'
    id = Column(Integer, primary_key=True, autoincrement=True)
    challenge_id = Column(Integer)
    type = Column(String(80))
    content = Column(Text)
    data = Column(Text)

class Hints(Base):
    __tablename__ = 'hints'
    id = Column(Integer, primary_key=True, autoincrement=True)
    type = Column(String(80))
    challenge_id = Column(Integer)
    content = Column(Text)
    cost = Column(Integer)
    requirements = Column(Text, CheckConstraint('json_valid(requirements)'))

class ManualChallenge(Base):
    __tablename__ = 'manual_challenge'
    id = Column(Integer, primary_key=True)

class MultipleChoice(Base):
    __tablename__ = 'multiple_choice'
    id = Column(Integer, primary_key=True)

class Notifications(Base):
    __tablename__ = 'notifications'
    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(Text)
    content = Column(Text)
    date = Column(DateTime)
    user_id = Column(Integer)
    team_id = Column(Integer)

class Pages(Base):
    __tablename__ = 'pages'
    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String(80))
    route = Column(String(128))
    content = Column(Text)
    draft = Column(Boolean)
    hidden = Column(Boolean)
    auth_required = Column(Boolean)

class Solves(Base):
    __tablename__ = 'solves'
    id = Column(Integer, primary_key=True)
    challenge_id = Column(Integer)
    user_id = Column(Integer)
    team_id = Column(Integer)

class Submissions(Base):
    __tablename__ = 'submissions'
    id = Column(Integer, primary_key=True, autoincrement=True)
    challenge_id = Column(Integer)
    user_id = Column(Integer)
    team_id = Column(Integer)
    ip = Column(String(46))
    provided = Column(Text)
    type = Column(String(32))
    date = Column(DateTime)

class Tags(Base):
    __tablename__ = 'tags'
    id = Column(Integer, primary_key=True, autoincrement=True)
    challenge_id = Column(Integer)
    value = Column(String(80))

class Teams(Base):
    __tablename__ = 'teams'
    id = Column(Integer, primary_key=True, autoincrement=True)
    oauth_id = Column(Integer)
    name = Column(String(128))
    email = Column(String(128))
    password = Column(String(128))
    secret = Column(String(128))
    website = Column(String(128))
    affiliation = Column(String(128))
    country = Column(String(32))
    bracket = Column(String(32))
    hidden = Column(Boolean)
    banned = Column(Boolean)
    created = Column(DateTime)
    captain_id = Column(Integer)

class Tracking(Base):
    __tablename__ = 'tracking'
    id = Column(Integer, primary_key=True, autoincrement=True)
    type = Column(String(32))
    ip = Column(String(46))
    user_id = Column(Integer)
    date = Column(DateTime)

class Unlocks(Base):
    __tablename__ = 'unlocks'
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer)
    team_id = Column(Integer)                   #all of this was created by Daniel Hansen
    target = Column(Integer)
    date = Column(DateTime)
    type = Column(String(32))

class Users(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, autoincrement=True)
    oauth_id = Column(Integer)
    name = Column(String(128))
    password = Column(String(128))
    email = Column(String(128))
    type = Column(String(80))
    secret = Column(String(128))
    website = Column(String(128))
    affiliation = Column(String(128))
    country = Column(String(32))
    bracket = Column(String(32))
    hidden = Column(Boolean)
    banned = Column(Boolean)
    verified = Column(Boolean)
    team_id = Column(Integer)
    created = Column(DateTime)


class DataAccessObject:
    def __init__(self, db_url):
        self.engine = create_engine(db_url, echo=False)
        self.Session = sessionmaker(bind=self.engine)
        self.session = self.Session()

    def create_database(self):
        if not database_exists(self.engine.url):
            create_database(self.engine.url)
        Base.metadata.create_all(self.engine)

    def get_config(self, key):
        """Retrieve a configuration setting."""
        config = self.session.query(Config).filter_by(key=key).first()
        return config.value if config else None

    def set_config(self, key, value):
        """Set a configuration setting."""
        config = self.session.query(Config).filter_by(key=key).first()
        if config:
            config.value = value
        else:
            config = Config(key=key, value=value)
            self.session.add(config)
        self.session.commit()

    def update_config_from_csv(self, csv_file_path):
        """Update the config table from a CSV file.

        :param csv_file_path: Path to the CSV file with key,value columns.
        All of this was created by Daniel Hansen
        
        """
        with open(csv_file_path, mode='r', encoding='utf-8') as csvfile:
            csvreader = csv.DictReader(csvfile)
            for row in csvreader:
                self.set_config(row['key'], row['value'])

    def add_user(self, user):
        self.session.add(user)
        self.session.commit()

    def get_user_by_id(self, user_id):
        return self.session.query(Users).filter_by(id=user_id).first()

    def add_user(self, name, email, password, **kwargs):
        """
        Add a new user to the database.

        :param name: Username
        :param email: Email address of the user
        :param password: Password (hashed using bcrypt_sha256)
        :param kwargs: Other attributes for the Users model
        """
        # Hash the password using bcrypt_sha256
        hashed_password = bcrypt_sha256.hash(password)

        # Use hashed_password instead of plain password
        new_user = Users(name=name, email=email, password=hashed_password, **kwargs)
        self.session.add(new_user)
        try:
            self.session.commit()
            print(f"User '{name}' added successfully.")
        except Exception as e:
            self.session.rollback()
            print(f"Error adding user '{name}': {e}")

    def add_team(self, name, email, **kwargs):
        """
        Add a new team to the database.

        :param name: Name of the team
        :param email: Email address of the team
        :param kwargs: Other attributes for the Teams model
        """
        new_team = Teams(name=name, email=email, **kwargs)
        self.session.add(new_team)
        try:
            self.session.commit()
            print(f"Team '{name}' added successfully.")
        except Exception as e:
            self.session.rollback()
            print(f"Error adding team '{name}': {e}")


    def add_challenge(self, **kwargs):
        """
        Add a new challenge to the database.
        """
        new_challenge = Challenges(**kwargs)
        self.session.add(new_challenge)
        self.session.commit()
        return new_challenge.id

    def add_flag(self, challenge_id, content, flag_type='static'):
        """
        Add a new flag to the database.
        """
        new_flag = Flags(challenge_id=challenge_id, content=content, type=flag_type)
        self.session.add(new_flag)
        self.session.commit()

    def add_tag(self, challenge_id, value):
        """
        Add a new tag to the database.

        :param challenge_id: The ID of the challenge the tag is associated with
        :param value: The value of the tag
        """
        new_tag = Tags(challenge_id=challenge_id, value=value.strip())
        self.session.add(new_tag)
        self.session.commit()

    def add_file(self, challenge_id, location):
        """
        Add a new file to the database.

        :param challenge_id: The ID of the challenge the file is associated with
        :param location: The location of the file
        """
        new_file = Files(challenge_id=challenge_id, location=location.strip())
        self.session.add(new_file)
        self.session.commit()

    def add_hint(self, challenge_id, content, cost=0):
        """
        Add a new hint to the database.

        :param challenge_id: The ID of the challenge the hint is associated with
        :param content: The content of the hint
        :param cost: The cost of the hint (optional)
        Creatd by Daniel Hansen
        """
        new_hint = Hints(challenge_id=challenge_id, content=content.strip(), cost=cost)
        self.session.add(new_hint)
        self.session.commit()

    def import_challenges_from_csv(self, csv_file_path):
        with open(csv_file_path, mode='r', encoding='utf-8') as csvfile:
            csvreader = csv.DictReader(csvfile)
            for row in csvreader:
                # Handle the challenge creation
                challenge_id = self.add_challenge(
                    name=row['name'],
                    description=row['description'],
                    max_attempts=int(row['max_attempts']) if row['max_attempts'] else 0,
                    value=int(row['value']) if row['value'] else 0,
                    category=row['category'],
                    type=row['type'],
                    state=row['state'],
                    requirements=json.loads(row['requirements']) if row['requirements'] else None
                )
                
                # Handle flags
                if row['flags']:
                    flags = json.loads(row['flags'])
                    for flag in flags:
                        self.add_flag(challenge_id=challenge_id, content=flag['content'], flag_type=flag['type'])

                # Handle files
                if row['files']:
                    files = json.loads(row['files'])
                    for file in files:
                        self.add_file(challenge_id=challenge_id, location=file['location'], file_type=file.get('type', 'standard'))

                # Handle hints
                if row['hints']:
                    hints = json.loads(row['hints'])
                    for hint in hints:
                        self.add_hint(challenge_id=challenge_id, content=hint['content'], cost=hint.get('cost', 0))

                # Handle tags
                if row['tags']:
                    tags = json.loads(row['tags'])
                    for tag in tags:
                        self.add_tag(challenge_id=challenge_id, value=tag)
     
                # Handle dynamic challenge
                if row['dynamic']:
                    dynamic_info = json.loads(row['dynamic'])
                    self.add_dynamic_challenge(
                        challenge_id=challenge_id,
                        initial=dynamic_info['initial'],
                        minimum=dynamic_info['minimum'],
                        decay=dynamic_info['decay']
                    )

                # Handle prerequisites
                if row['requirements']:
                    requirements = json.loads(row['requirements'])
                    # Here you would need to define how you want to handle prerequisites.
                    # For example, you might have a separate method to handle them
                    # and call it here.
                    self.add_prerequisites(challenge_id, requirements['prerequisites'])
    
    def create_admin_token(self, user_id, description="Admin token"):
        # Generate a unique token
        token_value = None
        while token_value is None or self.session.query(Token).filter_by(value=token_value).first() is not None:
            raw_token = os.urandom(32)
            token_value = "ctfd_" + raw_token.hex()

        # Current time and expiration time (e.g., 30 days from now)
        created_time = datetime.datetime.now()
        expiration_time = created_time + datetime.timedelta(days=30)

        # Insert the token into the database
        new_token = Token(type='default', user_id=user_id, created=created_time,
                        expiration=expiration_time, value=token_value, description=description)
        self.session.add(new_token)
        try:
            self.session.commit()
            return token_value
        except Exception as e:
            self.session.rollback()
            print(f"Error creating token: {e}")
            return None

    def get_user_by_username(self, username):
        """Retrieve a user by their username."""
        return self.session.query(Users).filter_by(name=username).first()
    
    def get_user_by_email(self, email):
        """Retrieve a user by their email."""
        return self.session.query(Users).filter_by(email=email).first()

    def get_token_by_username(self, username):
        """Retrieve the token value for a given username."""
        user = self.get_user_by_username(username)
        if user:
            token = self.session.query(Token).filter_by(user_id=user.id).first()
            return token.value if token else None
        else:
            print(f"User '{username}' not found.")
            return None
        
    def get_or_create_admin_token(self, username, description="Admin token"):
        # Check if the user exists
        user = self.get_user_by_username(username)
        if not user:
            print(f"User '{username}' not found. Creating user...\n")
            self.add_user(name=username, email=f'{username}@example.com', password='password123', type='admin')
            user = self.get_user_by_username(username)
            if not user:
                print("Failed to create user.")
                return None
        
        # Check if the user already has a token
        existing_token = self.session.query(Token).filter_by(user_id=user.id).first()
        if existing_token:
            print(f"Existing token found for user '{username}'.")
            return existing_token.value

        # Generate and return a new token
        return self.create_admin_token(user.id, description)
    
    
    def add_user_to_team(self, user_name, team_name):
        """
        Add a user to a specific team.

        :param user_name: Name of the user
        :param team_name: Name of the team
        """
        # Fetch the user and the team from the database
        user = self.session.query(Users).filter_by(name=user_name).first()
        team = self.session.query(Teams).filter_by(name=team_name).first()

        if user is None:
            print(f"User '{user_name}' not found.")
            return

        if team is None:
            # Create the team if it doesn't exist
            team = Teams(name=team_name)
            self.session.add(team)
            try:
                self.session.commit()
            except Exception as e:
                self.session.rollback()
                print(f"Error creating team '{team_name}': {e}")
                return

        # Add user to the team
        user.team_id = team.id
        try:
            self.session.commit()
            print(f"User '{user_name}' added to team '{team_name}'.")
        except Exception as e:
            self.session.rollback()
            print(f"Error adding user '{user_name}' to team '{team_name}': {e}")


    def add_prerequisites(self, challenge_id, prerequisites):
        # We need to define how prerequisites should be handled in the database.
        # This is a placeholder for the prerequisites logic. Daniel Hansen
        pass

    # Add other methods to interact with different tables

if __name__ == "__main__":
    # Parse command-line arguments
    args = parse_args()

    # Create a DataAccessObject instance with your database URL
    db_url = "mysql+pymysql://root:ctfd@db/ctfd"

    dao = DataAccessObject(db_url)

    # Update the configuration if a CSV file is provided
    if args.config_csv:
        dao.update_config_from_csv(args.config_csv)
        ctf_theme = dao.get_config("ctf_theme")
        print(f"CTF Theme: {ctf_theme}")


    # Generate or retrieve the admin token for given user
    if args.admin_token:
        username = args.admin_token
        token = dao.get_or_create_admin_token(username)
        if token:
            print(f"Admin token for '{username}': {token}") 
            dao.add_user_to_team(username, "Admins")
        else:
            print("Failed to retrieve or create admin token.")

    #dao.add_team(name="TEAMEXAMPLE", email="team@example.com", password="team_password", website="https://example.com", hidden=False, banned=False)
   
    # Import challenges from CSV
    #dao.import_challenges_from_csv("challenges.csv")


# Set a configuration setting
#dao.set_config("ctf_name", "My Awesome CTF")
#dao.set_config("ctf_theme", "core")
# Get a configuration setting


""" 
- awards
  - id: int(11) NOT NULL AUTO_INCREMENT
  - user_id: int(11) DEFAULT NULL
  - team_id: int(11) DEFAULT NULL
  - name: varchar(80) COLLATE utf8mb4_unicode_ci DEFAULT NULL
  - description: text COLLATE utf8mb4_unicode_ci DEFAULT NULL
  - date: datetime DEFAULT NULL
  - value: int(11) DEFAULT NULL
  - category: varchar(80) COLLATE utf8mb4_unicode_ci DEFAULT NULL
  - icon: text COLLATE utf8mb4_unicode_ci DEFAULT NULL
  - requirements: longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`requirements`))
  - type: varchar(80) COLLATE utf8mb4_unicode_ci DEFAULT 'standard'

- challenges
  - id: int(11) NOT NULL AUTO_INCREMENT
  - name: varchar(80) COLLATE utf8mb4_unicode_ci DEFAULT NULL
  - description: text COLLATE utf8mb4_unicode_ci DEFAULT NULL
  - max_attempts: int(11) DEFAULT NULL
  - value: int(11) DEFAULT NULL
  - category: varchar(80) COLLATE utf8mb4_unicode_ci DEFAULT NULL
  - type: varchar(80) COLLATE utf8mb4_unicode_ci DEFAULT NULL
  - state: varchar(80) COLLATE utf8mb4_unicode_ci NOT NULL
  - requirements: longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`requirements`))

- config
  - id: int(11) NOT NULL AUTO_INCREMENT
  - key: text COLLATE utf8mb4_unicode_ci DEFAULT NULL
  - value: text COLLATE utf8mb4_unicode_ci DEFAULT NULL

- dynamic_challenge
  - id: int(11) NOT NULL
  - initial: int(11) DEFAULT NULL
  - minimum: int(11) DEFAULT NULL
  - decay: int(11) DEFAULT NULL

- files
  - id: int(11) NOT NULL AUTO_INCREMENT
  - type: varchar(80) COLLATE utf8mb4_unicode_ci DEFAULT NULL
  - location: text COLLATE utf8mb4_unicode_ci DEFAULT NULL
  - challenge_id: int(11) DEFAULT NULL
  - page_id: int(11) DEFAULT NULL

- flags
  - id: int(11) NOT NULL AUTO_INCREMENT
  - challenge_id: int(11) DEFAULT NULL
  - type: varchar(80) COLLATE utf8mb4_unicode_ci DEFAULT NULL
  - content: text COLLATE utf8mb4_unicode_ci DEFAULT NULL
  - data: text COLLATE utf8mb4_unicode_ci DEFAULT NULL

- hints
  - id: int(11) NOT NULL AUTO_INCREMENT
  - type: varchar(80) COLLATE utf8mb4_unicode_ci DEFAULT NULL
  - challenge_id: int(11) DEFAULT NULL
  - content: text COLLATE utf8mb4_unicode_ci DEFAULT NULL
  - cost: int(11) DEFAULT NULL
  - requirements: longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`requirements`))

- manual_challenge
  - id: int(11) NOT NULL

- multiple_choice
  - id: int(11) NOT NULL

- notifications
  - id: int(11) NOT NULL AUTO_INCREMENT
  - title: text COLLATE utf8mb4_unicode_ci DEFAULT NULL
  - content: text COLLATE utf8mb4_unicode_ci DEFAULT NULL
  - date: datetime DEFAULT NULL
  - user_id: int(11) DEFAULT NULL
  - team_id: int(11) DEFAULT NULL

- pages
  - id: int(11) NOT NULL AUTO_INCREMENT
  - title: varchar(80) COLLATE utf8mb4_unicode_ci DEFAULT NULL
  - route: varchar(128) COLLATE utf8mb4_unicode_ci DEFAULT NULL
  - content: text COLLATE utf8mb4_unicode_ci DEFAULT NULL
  - draft: bool(1) DEFAULT NULL
  - hidden: bool(1) DEFAULT NULL
  - auth_required: bool(1) DEFAULT NULL

- solves
  - id: int(11) NOT NULL
  - challenge_id: int(11) DEFAULT NULL
  - user_id: int(11) DEFAULT NULL
  - team_id: int(11) DEFAULT NULL

- submissions
  - id: int(11) NOT NULL AUTO_INCREMENT
  - challenge_id: int(11) DEFAULT NULL
  - user_id: int(11) DEFAULT NULL
  - team_id: int(11) DEFAULT NULL
  - ip: varchar(46) COLLATE utf8mb4_unicode_ci DEFAULT NULL
  - provided: text COLLATE utf8mb4_unicode_ci DEFAULT NULL
  - type: varchar(32) COLLATE utf8mb4_unicode_ci DEFAULT NULL
  - date: datetime DEFAULT NULL

- tags
  - id: int(11) NOT NULL AUTO_INCREMENT
  - challenge_id: int(11) DEFAULT NULL
  - value: varchar(80) COLLATE utf8mb4_unicode_ci DEFAULT NULL

- teams
  - id: int(11) NOT NULL AUTO_INCREMENT
  - oauth_id: int(11) DEFAULT NULL
  - name: varchar(128) COLLATE utf8mb4_unicode_ci DEFAULT NULL
  - email: varchar(128) COLLATE utf8mb4_unicode_ci DEFAULT NULL
  - password: varchar(128) COLLATE utf8mb4_unicode_ci DEFAULT NULL
  - secret: varchar(128) COLLATE utf8mb4_unicode_ci DEFAULT NULL
  - website: varchar(128) COLLATE utf8mb4_unicode_ci DEFAULT NULL
  - affiliation: varchar(128) COLLATE utf8mb4_unicode_ci DEFAULT NULL
  - country: varchar(32) COLLATE utf8mb4_unicode_ci DEFAULT NULL
  - bracket: varchar(32) COLLATE utf8mb4_unicode_ci DEFAULT NULL
  - hidden: bool(1) DEFAULT NULL
  - banned: bool(1) DEFAULT NULL
  - created: datetime DEFAULT NULL
  - captain_id: int(11) DEFAULT NULL

- tracking
  - id: int(11) NOT NULL AUTO_INCREMENT
  - type: varchar(32) COLLATE utf8mb4_unicode_ci DEFAULT NULL
  - ip: varchar(46) COLLATE utf8mb4_unicode_ci DEFAULT NULL
  - user_id: int(11) DEFAULT NULL
  - date: datetime DEFAULT NULL

- unlocks
  - id: int(11) NOT NULL AUTO_INCREMENT
  - user_id: int(11) DEFAULT NULL
  - team_id: int(11) DEFAULT NULL
  - target: int(11) DEFAULT NULL
  - date: datetime DEFAULT NULL
  - type: varchar(32) COLLATE utf8mb4_unicode_ci DEFAULT NULL

- users
  - id: int(11) NOT NULL AUTO_INCREMENT
  - oauth_id: int(11) DEFAULT NULL
  - name: varchar(128) COLLATE utf8mb4_unicode_ci DEFAULT NULL
  - password: varchar(128) COLLATE utf8mb4_unicode_ci DEFAULT NULL
  - email: varchar(128) COLLATE utf8mb4_unicode_ci DEFAULT NULL
  - type: varchar(80) COLLATE utf8mb4_unicode_ci DEFAULT NULL
  - secret: varchar(128) COLLATE utf8mb4_unicode_ci DEFAULT NULL
  - website: varchar(128) COLLATE utf8mb4_unicode_ci DEFAULT NULL
  - affiliation: varchar(128) COLLATE utf8mb4_unicode_ci DEFAULT NULL
  - country: varchar(32) COLLATE utf8mb4_unicode_ci DEFAULT NULL
  - bracket: varchar(32) COLLATE utf8mb4_unicode_ci DEFAULT NULL
  - hidden: bool(1) DEFAULT NULL
  - banned: bool(1) DEFAULT NULL
  - verified: bool(1) DEFAULT NULL
  - team_id: int(11) DEFAULT NULL
  - created: datetime DEFAULT NULL
 """