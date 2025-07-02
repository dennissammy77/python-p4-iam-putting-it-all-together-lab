from sqlalchemy.orm import validates
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin

from config import db, bcrypt

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'
    
    serialize_rules = ('-recipes.user',)

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=False, unique=True)
    _password_hash = db.Column(db.String(100))
    image_url = db.Column(db.String)
    bio = db.Column(db.String)
    
    recipes = db.relationship('Recipe', back_populates='user', cascade='all, delete-orphan')

    @hybrid_property
    def password_hash(self):
        raise AttributeError('Password hashes may not be viewed.')

    @password_hash.setter
    def password_hash(self, password):
        password_hash = bcrypt.generate_password_hash(password.encode('utf-8'))
        self._password_hash = password_hash.decode('utf-8')
        
    def authenticate(self, password):
        return bcrypt.check_password_hash(self._password_hash, password.encode('utf-8'))
    
    @validates('username')
    def validate_username(self, key, username):
        if username in [x.username for x in User.query.all()]:
            raise ValueError('Username already exists')
        if not username:
            raise ValueError('Username is required')
        return username
        

class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'
    
    serialize_rules = ('-user.recipes',)
    
    # id, title, instructions, minutes_to_complete
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String(50), nullable=False)
    minutes_to_complete = db.Column(db.Integer)
    
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    user = db.relationship('User', back_populates='recipes')
    
    @validates('title')
    def validate_title(self, key, val):
        if not val:
            raise ValueError(f'{key} is required')
        return val
    
    @validates('instructions')
    def validate_instructions(self, key, instructions):
        if not instructions:
            raise ValueError(f'{key} is required')
        if len(instructions) < 50:
            raise ValueError('Instructions must be at least 50 characters')
        return instructions