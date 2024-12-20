from flask import Flask, render_template, redirect, url_for, session, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import os
import binascii
from dotenv import load_dotenv
import requests
from datetime import datetime
import plotly.express as px
import pandas as pd
import json
from github import Github
import requests

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = binascii.hexlify(os.urandom(24)).decode()  # Generate a random secret key
app.config['SESSION_TYPE'] = 'filesystem'  # Ensure session is stored correctly
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    github_id = db.Column(db.Integer, unique=True)
    username = db.Column(db.String(80), unique=True)
    access_token = db.Column(db.String(200))

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login')
def login():
    if current_user.is_authenticated:
        print('User is already authenticated, redirecting to dashboard.')  # Debug statement
        return redirect(url_for('dashboard'))
    github_auth_url = f"https://github.com/login/oauth/authorize?client_id={os.getenv('GITHUB_CLIENT_ID')}&scope=repo user"
    print('Redirecting to GitHub for authentication.')  # Debug statement
    return redirect(github_auth_url)

@app.route('/callback')
def callback():
    code = request.args.get('code')
    if code:
        print(f'Received code: {code}')  # Debug statement
        # Exchange code for access token
        response = requests.post(
            'https://github.com/login/oauth/access_token',
            data={
                'client_id': os.getenv('GITHUB_CLIENT_ID'),
                'client_secret': os.getenv('GITHUB_CLIENT_SECRET'),
                'code': code
            },
            headers={'Accept': 'application/json'}
        )
        access_token = response.json().get('access_token')
        print(f'Access token received: {access_token}')  # Debug statement
        
        # Get user info
        user_response = requests.get(
            'https://api.github.com/user',
            headers={'Authorization': f'token {access_token}'}
        )
        user_data = user_response.json()
        
        # Create or update user
        user = User.query.filter_by(github_id=user_data['id']).first()
        if not user:
            user = User(
                github_id=user_data['id'],
                username=user_data['login'],
                access_token=access_token
            )
            db.session.add(user)
        else:
            user.access_token = access_token
        db.session.commit()
        
        login_user(user)
        session['access_token'] = access_token  # Store access token in session
        print('User logged in successfully and access token stored in session.')  # Debug statement
        print(f'Session after login: {session}')  # Debug statement
        print(f'User authenticated: {current_user.is_authenticated}')  # Debug statement
        return redirect(url_for('dashboard'))
    print('No code received, redirecting to index.')  # Debug statement
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    access_token = session.get('access_token')
    if not access_token:
        return redirect(url_for('login'))

    try:
        github = Github(access_token)
        user = github.get_user()  # This is the GitHub user object
        
        # Collect comprehensive stats
        stats = {
            'username': user.login,  # Add username to stats
            'total_commits': calculate_total_commits(github, user),
            'total_prs': calculate_total_prs(github, access_token),
            'total_repos': len(list(user.get_repos())),
            'commit_increase': calculate_year_over_year_growth(github, user),
            'top_repos': get_top_repositories(github, user),
            'achievements': calculate_achievements(github, user)
        }
        
        print('Dashboard stats collected successfully.')
        return render_template('dashboard.html', stats=stats)
    except Exception as e:
        print(f"Error in dashboard: {str(e)}")
        return redirect(url_for('login'))

def calculate_total_commits(github, user):
    try:
        total = 0
        for repo in user.get_repos():
            try:
                commits = repo.get_commits(author=user, since=datetime(2024, 1, 1))
                total += commits.totalCount
            except Exception as e:
                print(f"Error counting commits for repo {repo.name}: {str(e)}")
                continue
        return total
    except Exception as e:
        print(f"Error in calculate_total_commits: {str(e)}")
        return 0

def calculate_total_prs(github, access_token):
    try:
        query = """
        query {
            viewer {
                pullRequests(first: 100, states: [MERGED], orderBy: {field: CREATED_AT, direction: DESC}) {
                    totalCount
                }
            }
        }
        """
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github.v4+json"
        }
        response = requests.post('https://api.github.com/graphql', 
                               json={'query': query}, 
                               headers=headers,
                               timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            return data['data']['viewer']['pullRequests']['totalCount']
        else:
            print(f"Error fetching PRs: {response.status_code}, {response.text}")
            return 0
    except Exception as e:
        print(f"Error in calculate_total_prs: {str(e)}")
        return 0

def get_top_repositories(github, user):
    try:
        repos = []
        for repo in user.get_repos():
            try:
                commits = repo.get_commits(since=datetime(2024, 1, 1))
                user_commits = repo.get_commits(author=user, since=datetime(2024, 1, 1))
                
                total_commits = commits.totalCount
                user_commits_count = user_commits.totalCount
                
                percentage = (user_commits_count / total_commits * 100) if total_commits > 0 else 0
                
                repos.append({
                    'name': repo.name,
                    'contribution_percentage': round(percentage, 1)
                })
            except Exception as e:
                print(f"Error processing repo {repo.name}: {str(e)}")
                continue
        
        # Sort by contribution percentage and return top 8
        return sorted(repos, key=lambda x: x['contribution_percentage'], reverse=True)[:8]
    except Exception as e:
        print(f"Error in get_top_repositories: {str(e)}")
        return []

def calculate_achievements(github, user):
    achievements = []
    
    # Night Owl Achievement
    night_commits = count_night_commits(github, user) or 0
    if night_commits > 10:
        achievements.append({
            'name': 'Night Owl',
            'description': 'Made over 10 commits at night',
            'icon': '/static/images/achievements/night-owl.svg'
        })
    
    # PR Master Achievement
    total_prs = calculate_total_prs(github, session.get('access_token'))
    if total_prs > 10:
        achievements.append({
            'name': 'PR Master',
            'description': 'Created over 10 pull requests',
            'icon': '/static/images/achievements/pr-master.svg'
        })
    
    # Active Developer Achievement
    total_commits = calculate_total_commits(github, user)
    if total_commits > 100:
        achievements.append({
            'name': 'Century Maker',
            'description': 'Made over 100 commits this year',
            'icon': '/static/images/achievements/century.svg'
        })
    
    # Repository Creator Achievement
    repo_count = len(list(user.get_repos()))
    if repo_count > 5:
        achievements.append({
            'name': 'Repository Creator',
            'description': 'Created more than 5 repositories',
            'icon': '/static/images/achievements/creator.svg'
        })
    
    return achievements

def count_night_commits(github, user):
    total_night_commits = 0
    try:
        for repo in user.get_repos():
            commits = repo.get_commits(author=user, since=datetime(2024, 1, 1))
            for commit in commits:
                commit_time = commit.commit.author.date.hour
                if 0 <= commit_time <= 5:  # Between midnight and 5 AM
                    total_night_commits += 1
    except Exception as e:
        print(f"Error counting night commits: {str(e)}")
        return 0
    return total_night_commits

def calculate_year_over_year_growth(github, user):
    # This function is not implemented in the provided code
    # You need to implement it according to your requirements
    pass

def extract_first_image_from_markdown(markdown_content):
    import re
    image_pattern = r'!\[.*?\]\((.*?)\)'
    match = re.search(image_pattern, markdown_content)
    return match.group(1) if match else None

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
