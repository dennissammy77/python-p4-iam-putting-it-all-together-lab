#!/usr/bin/env python3

from flask import request, session, jsonify
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

@app.before_request
def check_login():
    if request.endpoint in ('recipes',) and not session.get('user_id'):
        return {'error': 'Unauthorized'}, 401

class Signup(Resource):
    def post(self):
        try:
            json = request.get_json()
            user = User(
                username=json['username'],
                image_url=json['image_url'],
                bio=json['bio']
            )
            user.password_hash = json['password']
            db.session.add(user)
            db.session.commit()
            session['user_id'] = user.id
            
            return user.to_dict(), 201
        
        except Exception as e:
            return {'error': str(e)}, 422
        

class CheckSession(Resource):
    def get(self):
        if id := session.get('user_id'):
            user = User.query.filter_by(id=id).first()
            return user.to_dict(), 200
        return {"error": "Not logged in"}, 401

class Login(Resource):
    
    def post(self):
        username, password = request.get_json()['username'], request.get_json()['password']
        user = User.query.filter_by(username=username).first()

        if user and user.authenticate(password):
            session['user_id'] = user.id
            return user.to_dict(), 200
        return {"error": "Invalid username or password"}, 401
    
    
class Logout(Resource):
    
    def delete(self):
        if session.get('user_id'):
            session['user_id'] = None
            return {}, 204
        return {'error': 'No user is currently logged in'}, 401

class RecipeIndex(Resource):
    
    def post(self):
        try:
            user = User.query.filter_by(id=session.get('user_id')).first()
            json = request.get_json()
            recipe = Recipe(
                title=json['title'],
                instructions=json['instructions'],
                minutes_to_complete=json['minutes_to_complete'] 
            )
            recipe.user=user
            db.session.add_all([user, recipe])
            db.session.commit()
            return recipe.to_dict(), 201
        except Exception as e:
            return {"error": str(e)}, 422
        
    
    def get(self):
        user = User.query.filter_by(id = session.get('user_id')).first()
        return [recipe.to_dict() for recipe in user.recipes], 200
    
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)