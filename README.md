# GitHub Year in Review

A web-based application that generates a personalized Year-in-Review for developers, similar to Spotify Wrapped but for your GitHub activity. Get beautiful visualizations and insights about your coding journey throughout the year.

## Features

- 📊 Comprehensive GitHub activity visualization
- 🏆 Personal coding achievements and milestones
- 📈 Language usage statistics and trends
- 🌟 Project contribution insights
- 🤝 Community engagement metrics
- 📱 Shareable cards for social media

## Setup

1. Clone the repository
```bash
git clone https://github.com/XxAlonexX/Year-Review.git
cd Year-Review
```

2. Install dependencies
```bash
pip install -r requirements.txt
```

3. Set up environment variables
Create a `.env` file in the root directory with:
```
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret
SECRET_KEY=your_flask_secret_key
```

4. Run the application
```bash
python app.py
```

## Tech Stack

- Backend: Flask (Python)
- Frontend: HTML, CSS, JavaScript
- Data Visualization: Plotly
- Authentication: GitHub OAuth
- Database: SQLAlchemy

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
