from datetime import datetime, timedelta
from sqlalchemy import func
from decouple import config
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask import Flask, render_template, request, jsonify, make_response, url_for
from marshmallow import Schema, fields, validates, ValidationError, validate
from password_strength import PasswordPolicy
from werkzeug.security import generate_password_hash, check_password_hash
from dash_app import build_dash
import jwt

app = Flask(__name__)

db_user = config('DB_USER')
db_password = config("DB_PASSWORD")
database = config("DATABASE")

app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{db_user}:{db_password}@localhost:5432/{database}'
db = SQLAlchemy(app)
migrate = Migrate(app, db)

build_dash(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), nullable=False, unique=True)
    email = db.Column(db.String(120))
    password = db.Column(db.String(255), nullable=False)
    create_on = db.Column(db.DateTime, server_default=func.now())
    updated_on = db.Column(db.DateTime, onupdate=func.now())

    def encode_token(self):
        try:
            payload = {
                'exp': datetime.utcnow() + timedelta(days=2),
                'sub': self.id
            }
            return jwt.encode(
                payload,
                key=config('SECRET_KEY'),
                algorithm='HS256'
            )
        except Exception as e:
            raise e


class BaseUserSchema(Schema):
    username = fields.String(required=True)
    password = fields.String(required=True, validate=validate.And(validate.Length(min=8, max=20)))

    @validates("username")
    def validate_name(self, value):
        if len(value) < 4:
            raise ValueError("Name should be at least 4 latters long")

    @validates("password")
    def validate_password(self, value):
        errors = PasswordPolicy.from_names(
            uppercase=1,
        ).test(value)
        if errors:
            raise ValidationError("Not a valid password")


@app.route("/")
def homepage():
    token = request.cookies.get('token')
    if token:
        data = jwt.decode(token, config('SECRET_KEY'), algorithms=["HS256"])
        user = User.query.filter_by(id=data['sub']).first()
    return render_template('index.html', utc_dt=datetime.utcnow(), username=user.username)
#
# @app.route("/dash")
# def dashboard():
#     build_dash(app)
#     return url_for('dash_live')


@app.route("/register", methods=['POST'])
def register():
    if request.method == "POST":
        data = request.form.to_dict()
        schema = BaseUserSchema()
        errors = schema.validate(data)
        if not errors:
            data["password"] = generate_password_hash(data['password'], method='sha256')
            db.session.add(User(**data))
            db.session.commit()
            return data

        return errors #json - field: list of erros


@app.route("/login", methods=['POST'])
def login():
    if request.method == "POST":
        data = request.form.to_dict()
        schema = BaseUserSchema()
        errors = schema.validate(data)
        if not errors:
            user = User.query.filter_by(username=data['username']).first()
            logged_in = check_password_hash(user.password, data['password'])
            if logged_in:
                resp = make_response(render_template('index.html', utc_dt=datetime.utcnow(), username=user.username))
                token = user.encode_token()
                resp.set_cookie('token', token)
                return resp
            else:
                return "Wrong Password"
        return errors  # json - field: list of errors


if __name__ == "__main__":
    db.create_all()
    app.run(debug=True)
