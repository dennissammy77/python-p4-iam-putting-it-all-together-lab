#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError
from config import app, db, api
from models import User, Recipe


class Signup(Resource):
    def post(self):
        if not request.is_json:
            return {'errors': ['Request must be JSON']}, 400

        data = request.get_json()

        if not data.get('password'):
            return {'errors': ['Password is required.']}, 422

        try:
            user = User(
                username=data.get('username'),
                image_url=data.get('image_url'),
                bio=data.get('bio')
            )
            user.password_hash = data.get('password')

            db.session.add(user)
            db.session.commit()

            session['user_id'] = user.id

            return user.to_dict(), 201

        except (ValueError, IntegrityError) as e:
            db.session.rollback()
            return {'errors': [str(e)]}, 422


class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')

        if user_id:
            user = db.session.get(User, user_id)
            if user:
                return user.to_dict(), 200

        return {'error': 'Unauthorized'}, 401


class Login(Resource):
    def post(self):
        if not request.is_json:
            return {'errors': ['Request must be JSON']}, 400

        data = request.get_json()

        user = User.query.filter_by(username=data.get('username')).first()

        if user and user.authenticate(data.get('password')):
            session['user_id'] = user.id
            return user.to_dict(), 200

        return {'error': 'Invalid username or password'}, 401


class Logout(Resource):
    def delete(self):
        user_id = session.get('user_id')
        if user_id:
            session.pop('user_id')
            return '', 204

        return {'error': 'Unauthorized'}, 401


class RecipeIndex(Resource):
    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            return {'error': 'Unauthorized'}, 401

        recipes = Recipe.query.all()
        return [r.to_dict() for r in recipes], 200

    def post(self):
        if not request.is_json:
            return {'errors': ['Request must be JSON']}, 400

        user_id = session.get('user_id')
        if not user_id:
            return {'error': 'Unauthorized'}, 401

        data = request.get_json()

        try:
            recipe = Recipe(
                title=data.get('title'),
                instructions=data.get('instructions'),
                minutes_to_complete=data.get('minutes_to_complete'),
                user_id=user_id
            )

            db.session.add(recipe)
            db.session.commit()

            return recipe.to_dict(), 201

        except ValueError as e:
            db.session.rollback()
            return {'errors': [str(e)]}, 422

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)