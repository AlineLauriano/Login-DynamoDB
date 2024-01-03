from boto3.dynamodb.conditions import Key, Attr
from flask import Flask, render_template, request
import key_config as keys
import boto3 #interação com dynamoDB
import hashlib #hashing de senhas
import re #regex - processamento de strings

app = Flask(__name__)


dynamodb = boto3.resource('dynamodb',
                          aws_access_key_id=keys.ACCESS_KEY_ID,
                          aws_secret_access_key=keys.ACCESS_SECRET_KEY,
                          aws_session_token=keys.AWS_SESSION_TOKEN,
                          region_name='us-east-1')


def email_exists(email):
    # Função para verificar se o e-mail já existe na tabela
    table = dynamodb.Table('users')
    response = table.query(
        KeyConditionExpression=Key('email').eq(email)
    )
    return len(response['Items']) > 0

# Função para inserir complexidade na senha
def is_password_strong(password):
    if len(password) < 4:
        return False
    if re.search(r'[A-Z]', password) is None:
        return False
    if re.search(r'[a-z]', password) is None:
        return False
    if re.search(r'[0-9]', password) is None:
        return False
    if re.search(r'[^a-zA-Z0-9]', password) is None:
        return False
    if password == '123':
        return False
    return True

@app.route('/')
def index():
    return render_template('index.html')

#Recebe o formulário de cadastro do novo usuário
@app.route('/signup', methods=['POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        if not is_password_strong(password):
            msg = "Senha fraca. Por favor, use uma senha mais forte!"
            return render_template('index.html', msg=msg)

        # Verifica se o e-mail já existe
        if email_exists(email):
            msg = "Email já cadastrado. Por favor cadastre outro email!"
            return render_template('index.html', msg=msg)

        # Cria um hash da senha antes de armazená-la
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        table = dynamodb.Table('users')

        table.put_item(
            Item={
                'name': name,
                'email': email,
                'password': hashed_password  # Armazena o hash da senha no banco de dados
            }
        )
        msg = "Registro efetuado!"

        return render_template('login.html', msg=msg)
    return render_template('index.html')

@app.route('/login')
def login():    
    return render_template('login.html')

#Recebe email e senha do formulário de cadastro
@app.route('/check', methods=['POST'])
def check():
    if request.method == 'POST':

        email = request.form['email']
        password = request.form['password']

        table = dynamodb.Table('users')
        response = table.query(
            KeyConditionExpression=Key('email').eq(email)
        )
        items = response['Items']

        # Se o e-mail existe no banco de dados
        if len(items) > 0:
            stored_password = items[0]['password']  # Obtém o hash da senha armazenada no banco de dados
            input_password_hash = hashlib.sha256(password.encode()).hexdigest()  # Converta a senha fornecida em hash

            # Compare os hashes das senhas
            if input_password_hash == stored_password:
                name = items[0]['name']
                return render_template("home.html", name=name)
        
        # Se o e-mail não existir ou a senha estiver incorreta
        return render_template("login.html", msg="Email ou senha incorretos.")

    return render_template("login.html")

@app.route('/home')
def home():
    return render_template('home.html')





if __name__ == "__main__":

    app.run(debug=True)
