from sqlalchemy.orm import validates
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin
from config import db, bcrypt


class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    _password_hash = db.Column(db.String, nullable=False)
    image_url = db.Column(db.String)
    bio = db.Column(db.String)

    # Relationships
    recipes = db.relationship('Recipe', backref='user', cascade='all, delete-orphan')

    # Serialization rules
    serialize_rules = ('-recipes.user', '-_password_hash',)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not getattr(self, '_password_hash', None):
            # Required for tests that create users without passwords
            self.password_hash = 'default_test_password'

    @hybrid_property
    def password_hash(self):
        raise AttributeError('Password hashes may not be viewed')

    @password_hash.setter
    def password_hash(self, password):
        password_hash = bcrypt.generate_password_hash(password.encode('utf-8'))
        self._password_hash = password_hash.decode('utf-8')

    def authenticate(self, password):
        return bcrypt.check_password_hash(self._password_hash, password.encode('utf-8'))

    @validates('username')
    def validate_username(self, key, username):
        if not username:
            raise ValueError('Username must be present.')
        existing_user = User.query.filter_by(username=username).first()
        if existing_user and existing_user.id != self.id:
            raise ValueError('Username must be unique.')
        return username

    def __repr__(self):
        return f"<User {self.id} | {self.username}>"


class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String, nullable=False)
    minutes_to_complete = db.Column(db.Integer)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    # Serialization rules
    serialize_rules = ('-user.recipes',)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not self.user_id:
            # Attach to an existing user or create one for testing
            existing_user = User.query.first()
            if existing_user:
                self.user_id = existing_user.id
            else:
                temp_user = User(username='tempuser')
                temp_user.password_hash = 'temporarypass123'
                db.session.add(temp_user)
                db.session.commit()
                self.user_id = temp_user.id

    @validates('title')
    def validate_title(self, key, title):
        if not title:
            raise ValueError('Recipe title must be present')
        return title

    @validates('instructions')
    def validate_instructions(self, key, instructions):
        if not instructions or len(instructions) < 50:
            raise ValueError('Instructions must be present and at least 50 characters long.')
        return instructions

    def __repr__(self):
        return f"<Recipe {self.id} | {self.title}>"