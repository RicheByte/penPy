from flask import Flask, request, render_template_string

app = Flask(__name__)

# Vulnerable endpoints for testing
@app.route('/')
def home():
    return '''
    <h1>Test Server</h1>
    <a href="/search?q=test">Search</a>
    <a href="/contact">Contact</a>
    <form action="/login" method="post">
        <input name="username" value="admin">
        <input name="password" value="password">
        <input type="submit">
    </form>
    '''

@app.route('/search')
def search():
    query = request.args.get('q', '')
    return f'<h1>Search Results for: {query}</h1>'

@app.route('/contact')
def contact():
    return '<h1>Contact Page</h1><form method="post"><input name="message"><input type="submit"></form>'

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    return f'<h1>Login attempt for: {username}</h1>'

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)