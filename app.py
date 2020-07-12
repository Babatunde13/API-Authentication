from flask import Flask, request, make_response, jsonify
from flask_sqlalchemy import SQLAlchemy 
import uuid, jwt
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

app.config['SECRET_KEY']='mysecretkey'
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///site.db'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password=db.Column(db.String(80))
    admin=db.Column(db.Boolean)

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(50))
    complete = db.Column(db.Boolean)
    user_id=db.Column(db.Integer)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token: 
            return jsonify({'message': 'Token is missing'})

        try:
            data=jwt.decode(token, app.config['SECRET_KEY'])
            current_user=User.query.filter_by(public_id=data['public_id']).first()

        except:
            return jsonify({'message': 'Token is invalid'})

        return f(current_user, *args, **kwargs)

    return decorated
    

@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that operaation'})

    all_user=User.query.all()
    output = []

    for user in all_user:
        user_data  ={}
        user_data['name']=user.name
        user_data['admin']=user.admin
        user_data['password']=user.password
        user_data['public_id']=user.public_id
        output.append(user_data)

    return jsonify({'users': output})

@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user ,public_id):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that operaation'})

    user=User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'Message': 'No user found'})

    user_data = {}
    user_data['name']=user.name
    user_data['admin']=user.admin
    user_data['password']=user.password
    user_data['public_id']=user.public_id

    return jsonify({'user': user_data})


@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that operaation'})

    data=request.get_json()
    hashed_password=generate_password_hash(data['password'])
    new_user=User(public_id=str(uuid.uuid4()),
                  name=data['name'],
                  password=hashed_password,
                  admin=False)

    db.session.add(new_user)
    db.session.commit()
    return jsonify({'Message': 'New User Created!'})

@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that operaation'})

    user=User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'Message': 'No user found'})

    user.admin = True
    db.session.commit()

    return jsonify({'message': 'User has been promoted'})

@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that operaation'})

    user=User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'Message': 'No user found'})

    db.session.delete(user)
    db.session.commit()
    return jsonify({'Message': 'User has been deleted!'})

@app.route('/login')
def login():
    import datetime as dt
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate': \
                                                        'Basic realm="Login required!'})

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 
                                                        'Basic realm="Login required!'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id': user.public_id, 'exp': dt.datetime.utcnow()+dt.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        return jsonify({'Token': token.decode('utf-8')})
    
    return make_response('Could not verify', 401, {'WWW-Authenticate': \
                                                'Basic realm="Login required!'})

@app.route('/todo', methods=['GET'])
@token_required
def get_all_todos(current_user):
    all_todo=Todo.query.filter_by(user_id=current_user.id).all()
    output = []

    for todo in all_todo:
        todo_data  ={}
        todo_data['id']=todo.id
        todo_data['text']=todo.text
        todo_data['complete']=todo.complete
        output.append(todo_data)

    return jsonify({'todos': output})

@app.route('/todo/<todo_id>', methods=['GET'])
@token_required
def get_one_todo(current_user, todo_id):
    todo=Todo.query.filter_by(id=todo_id, user_id=current_user.id).first()

    if not todo:
        return jsonify({'Message': 'No todo found'})

    todo_data = {}
    todo_data['id']=todo.id
    todo_data['text']=todo.text
    todo_data['complete']=todo.complete

    return jsonify({'todo': todo_data})


@app.route('/todo', methods=['POST'])
@token_required
def create_todo(current_user):
    data=request.get_json()

    new_todo=Todo(text=data['text'],
                  user_id=current_user.id,
                  complete=False)

    db.session.add(new_todo)
    db.session.commit()
    return jsonify({'Message': 'New todo Created!'})

@app.route('/todo/<todo_id>', methods=['PUT'])
@token_required
def complete_todo(current_user, todo_id):
    todo=Todo.query.filter_by(id=todo_id,user_id=current_user.id).first()

    if not todo:
        return jsonify({'Message': 'No todo found'})

    todo.complete = True
    db.session.commit()
    return jsonify({'message': 'todo has been completed'})

@app.route('/todo/<todo_id>', methods=['DELETE'])
@token_required
def delete_todo(current_user, todo_id):
    todo=Todo.query.filter_by(id=todo_id, user_id=current_user.id).first()

    if not todo:
        return jsonify({'Message': 'No todo found'})
    db.session.delete(todo)
    db.session.commit()
    
    return jsonify({'Message': 'todo has been deleted!'})


if __name__ == "__main__":
    app.run(debug=True)