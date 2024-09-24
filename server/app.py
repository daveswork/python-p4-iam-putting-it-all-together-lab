#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        data = request.get_json()
        if data.get('username') is None:
            return {'Error': 'Invalid user data.'}, 422

        user = User(
            username=request.get_json().get('username'),
        )
        user.password_hash=data.get('password')
        user.image_url=data.get('image_url')
        user.bio=request.get_json().get('bio')
        if not user:
            return {'Error': 'Invalid user data.'}, 422
        else:
            db.session.add(user)
            db.session.commit()
            session['user_id'] = user.id
            return user.to_dict(), 201

        pass

class CheckSession(Resource):

    def get(self):
        if session.get('user_id'):
            user = User.query.filter(User.id == session['user_id']).first()
            return user.to_dict(),200
        else:
            return {'Error':'Unauthorized'}, 401
    pass

class Login(Resource):
    def post(self):
        username = request.get_json()['username']
        password = request.get_json()['password']
        user = User.query.filter(User.username == username).first()
        if user is not None and user.authenticate(password):
            session['user_id'] = user.id
            return user.to_dict(), 200
        else:
            return {'Error':'Unauthorized'},401


class Logout(Resource):
    def delete(self):
        if session.get('user_id'):
            session.pop('user_id')
            return "",204
        else:
            return {'Error':'Unauthorized'}, 401
        

class RecipeIndex(Resource):
    def get(self):
        if not session.get('user_id'):
            return {'Error':'Unauthorized'}, 401
        else:
            recipies = Recipe.query.filter_by(user_id=session.get('user_id')).all()
            return [recipe.to_dict() for recipe in recipies],200
    
    def post(self):
        data = request.get_json()
        if not session.get('user_id'):
            return {'Error': 'Unauthorized'}, 401
        else:
            try:
                recipe = Recipe(
                    title=data.get('title'),
                    instructions=data.get('instructions'),
                    minutes_to_complete=data.get('minutes_to_complete'),
                    user_id=session.get('user_id')
                )
            except:
                return {'Error':'Invalid recipe'},422
            if not recipe:
                return {'Error':'Invalid recipe'},422
            else:
                db.session.add(recipe)
                db.session.commit()
                return recipe.to_dict(), 201 

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)