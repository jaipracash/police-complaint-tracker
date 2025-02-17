from datetime import datetime

from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO, emit, join_room
import os
from flask import flash, redirect, url_for, session


app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your_secret_key')
DB_USERNAME = "uds67epwmwjx6izv"
DB_PASSWORD = "mDHWTFY3FcYCpLsDAq1V"
DB_HOST = "birtrviqdlzckt1cjhp2-mysql.services.clever-cloud.com"
DB_NAME = "birtrviqdlzckt1cjhp2"
DB_PORT = 3306  # MySQL default port

app.config["SQLALCHEMY_DATABASE_URI"] = f"mysql+pymysql://{DB_USERNAME}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False


# app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://jai:admin123@127.0.0.1:3306/common_contributions_tracker'
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*")

login_manager = LoginManager()
login_manager.init_app(app)

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)


class Complaint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)

    # Define the relationship with Request
    related_requests = db.relationship('Request', backref='complaint', lazy=True)

class Request(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    complaint_id = db.Column(db.Integer, db.ForeignKey('complaint.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    admin_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    # Relationships
    user = db.relationship('User', foreign_keys=[user_id])
    admin = db.relationship('User', foreign_keys=[admin_id])

@app.route('/user_pending_requests')
@login_required
def user_pending_requests():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))

    # Fetch pending requests for the current user
    requests = Request.query.filter_by(user_id=current_user.id, status='pending').all()
    return render_template('user_dashboard.html', requests=requests, show_pending=True)

@app.route('/user_approved_requests')
@login_required
def user_approved_requests():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))

    # Fetch approved requests for the current user
    requests = Request.query.filter_by(user_id=current_user.id, status='approved').all()
    return render_template('user_dashboard.html', requests=requests, show_approved=True)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.Integer, db.ForeignKey('request.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)  # Add ondelete='CASCADE'
    message = db.Column(db.Text, nullable=False)
    admin_reply = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

    # Define the relationship to the User model
    user = db.relationship('User', backref=db.backref('messages', cascade="all, delete"))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    return redirect(url_for('login'))



@app.route('/request_status')
def request_status():
    # Fetch both pending and approved requests
    requests = Request.query.all()  # Modify this as per your database query
    return render_template('user_dashboard.html', show_requests=True, requests=requests)

# Load user for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Route to view all users
@app.route('/view_all_users')
@login_required
def view_all_users():
    if current_user.is_admin != True:
        flash("You do not have permission to access this page.", "danger")
        return redirect(url_for('admin_dashboard'))
    users = User.query.all()  # Fetch all users from the database
    return render_template('users.html', users=users)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        if user and user.password == password:
            login_user(user)
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html')

with app.app_context():
    db.create_all()
    # Predefined complaints
    predefined_complaints = [
        {"title": "Theft", "description": "Report stolen items or property."},
        {"title": "Burglary", "description": "Report unauthorized entry into a property."},
        {"title": "Assault", "description": "Report physical harm or threats."},
        {"title": "Fraud", "description": "Report scams or financial fraud."},
        {"title": "Noise Complaint", "description": "Report excessive noise or disturbances."},
        {"title": "Vandalism", "description": "Report property damage or destruction."},
        {"title": "Harassment", "description": "Report unwanted or threatening behavior."},
        {"title": "Traffic Violation", "description": "Report reckless driving or traffic violations."},
        {"title": "Missing Person", "description": "Report a missing individual."},
        {"title": "Domestic Violence", "description": "Report abuse or violence in a domestic setting."},
    ]

    # Insert predefined complaints into the database
    for complaint_data in predefined_complaints:
        if not Complaint.query.filter_by(title=complaint_data["title"]).first():
            new_complaint = Complaint(title=complaint_data["title"], description=complaint_data["description"])
            db.session.add(new_complaint)
    db.session.commit()


@app.route('/request_help/<int:complaint_id>', methods=['POST'])
@login_required
def request_help(complaint_id):
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))

    # Create a new request
    new_request = Request(user_id=current_user.id, complaint_id=complaint_id)
    db.session.add(new_request)
    db.session.commit()

    flash('Request sent to admin. Please wait for approval.', 'success')
    return redirect(url_for('user_dashboard'))


@app.route('/user_dashboard')
@login_required
def user_dashboard():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))

    complaints = Complaint.query.all()
    return render_template('user_dashboard.html', complaints=complaints, show_complaints=True)

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        return "Unauthorized", 403

    # Fetch pending requests
    requests = Request.query.filter_by(status='pending').all()
    return render_template('admin_dashboard.html', requests=requests, pending=True)

@app.route('/approved_requests')
@login_required
def approved_requests():
    if not current_user.is_admin:
        return "Unauthorized", 403

    # Fetch approved requests
    requests = Request.query.filter_by(status='approved').all()
    return render_template('admin_dashboard.html', requests=requests, pending=False)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))
@app.route('/approve_request/<int:request_id>', methods=['POST'])
@login_required
def approve_request(request_id):
    if not current_user.is_admin:
        return "Unauthorized", 403

    req = Request.query.get(request_id)
    if req:
        req.status = 'approved'
        req.admin_id = current_user.id
        db.session.commit()

        flash('Request approved successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/chat/<int:request_id>')
@login_required
def chat(request_id):
    request = Request.query.get(request_id)
    if not request:
        flash('Invalid request.', 'danger')
        return redirect(url_for('user_dashboard'))

    # Ensure only the user or admin can access the chat
    if not (current_user.id == request.user_id or current_user.is_admin):
        return "Unauthorized", 403

    messages = Message.query.filter_by(request_id=request_id).all()
    return render_template('chat.html', request=request, messages=messages)

@socketio.on('send_message')
@login_required
def handle_message(data):
    request_id = data['request_id']
    message_text = data['message']

    # Save the message to the database
    new_message = Message(
        request_id=request_id,
        user_id=current_user.id,
        message=message_text
    )
    db.session.add(new_message)
    db.session.commit()

    # Emit the message to all clients in the room
    emit('new_message', {
        'request_id': request_id,
        'user_id': current_user.id,
        'username': current_user.username,
        'message': message_text,
        'timestamp': new_message.timestamp.strftime('%Y-%m-%d %H:%M:%S')
    }, room=str(request_id))

@socketio.on('join_room')
@login_required
def handle_join_room(data):
    request_id = data['request_id']
    join_room(str(request_id))  # Join the room for the current request

@socketio.on('send_reply')
@login_required
def handle_reply(data):
    message_id = data['message_id']
    reply_text = data['reply']

    # Ensure current_user is valid
    if not current_user.is_authenticated or not current_user.id:
        emit('error', {'message': 'User not authenticated.'})
        return

    # Fetch the message
    message = Message.query.get(message_id)
    if not message:
        emit('error', {'message': 'Message not found.'})
        return

    # Ensure the current user is an admin
    if not current_user.is_admin:
        emit('error', {'message': 'You do not have permission to reply.'})
        return

    # Update the message
    message.admin_reply = reply_text
    db.session.commit()

    # Emit the reply to all clients in the room
    emit('new_reply', {
        'message_id': message_id,
        'reply': reply_text
    }, room=str(message.request_id))

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/help-support')
def help_support():
    return render_template('help_support.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Check if the username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'danger')
            return redirect(url_for('register'))

        # Create a new user
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/promote_admin/<int:user_id>', methods=['POST'])
@login_required
def promote_admin(user_id):
    if current_user.is_admin != True:
        flash("You do not have permission to perform this action.", "danger")
        return redirect(url_for('admin_dashboard'))
    user = db.session.get(User, user_id)
    if user and user.is_admin != True:
        user.is_admin = True
        db.session.commit()
        flash(f"{user.username} is now an admin.", "success")
    return redirect(url_for('view_all_users'))

# Route to delete a user
@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.is_admin != True:
        flash("You do not have permission to perform this action.", "danger")
        return redirect(url_for('admin_dashboard'))

    user = db.session.get(User, user_id)
    if user:
        # Delete all messages associated with the user
        Message.query.filter_by(user_id=user.id).delete()

        db.session.delete(user)
        db.session.commit()
        flash(f"{user.username} has been deleted.", "danger")
    return redirect(url_for('view_all_users'))
@app.route('/close_room/<int:request_id>', methods=['POST'])
@login_required
def close_room(request_id):
    if not current_user.is_admin:
        flash("You do not have permission to perform this action.", "danger")
        return redirect(url_for('admin_dashboard'))

    req = Request.query.get(request_id)
    if req:
        req.status = 'closed'  # Update status to 'closed'
        db.session.commit()
        flash('Room closed successfully!', 'success')
    return redirect(url_for('approved_requests'))

@app.route('/decline_request/<int:request_id>', methods=['POST'])
@login_required
def decline_request(request_id):
    if not current_user.is_admin:
        flash("You do not have permission to perform this action.", "danger")
        return redirect(url_for('admin_dashboard'))

    req = Request.query.get(request_id)
    if req:
        req.status = 'declined'  # Update status to 'declined'
        db.session.commit()
        flash('Request declined successfully!', 'danger')
    return redirect(url_for('admin_dashboard'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, debug=True, host='127.0.0.1', port=5000)
