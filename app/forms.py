from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField,TextAreaField,FloatField, FileField
from wtforms.validators import DataRequired, Email, Length, EqualTo 
from flask_wtf.file import FileAllowed, FileField


class SignupForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=50)])
    email = StringField("Email", validators=[DataRequired(), Email()])
    phone = StringField("Phone Number", validators=[DataRequired(), Length(min=10, max=15)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField(
        "Confirm Password", 
        validators=[DataRequired(), EqualTo('password')]
    )
    submit = SubmitField("Create Account")


class ContactForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    message = TextAreaField("Message", validators=[DataRequired()])
    submit = SubmitField("Send")


class ProductForm(FlaskForm):
    name = StringField("Product Name", validators=[DataRequired()])
    price = FloatField("Price (Ksh)", validators=[DataRequired()])
    image = FileField("Product Image", validators=[FileAllowed(['jpg', 'jpeg', 'png', 'webp','avif','gif'])])
    submit = SubmitField("Add Product")
    
class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")
