# CybrScan - White-Label Security Scanner Platform

CybrScan is a comprehensive white-label security scanning platform designed for Managed Service Providers (MSPs) to offer customizable security scanning services to their clients.

## Features

- **Multi-tenant Architecture**: Manage multiple clients with isolated data
- **Customizable Security Scanners**: Brand scanners with client logos and colors
- **Comprehensive Security Scanning**:
  - SSL/TLS certificate verification
  - DNS record analysis
  - Port scanning
  - Security header validation
  - Vulnerability detection
- **Lead Generation**: Capture and manage potential client leads
- **Subscription Management**: Multiple tiers with Stripe integration
- **API Support**: RESTful API for scanner integration
- **Email Notifications**: Automated alerts and reports

## Technology Stack

- **Backend**: Python 3.11, Flask 2.2.3
- **Database**: PostgreSQL (production), SQLite (development)
- **Authentication**: Flask-Login
- **Payment Processing**: Stripe
- **Email**: Flask-Mail
- **Production Server**: Gunicorn

## Deployment on Render.com

### Prerequisites

1. A Render.com account
2. A GitHub account
3. Stripe account for payment processing (optional)
4. SMTP email service credentials (optional)

### Step 1: Prepare Your Repository

1. Fork or clone this repository to your GitHub account
2. Ensure all files are committed and pushed to GitHub

### Step 2: Deploy to Render

1. Log in to [Render.com](https://render.com)
2. Click "New +" and select "Blueprint"
3. Connect your GitHub repository
4. Select the repository containing CybrScan_render
5. Render will automatically detect the `render.yaml` file and configure your services

### Step 3: Configure Environment Variables

In the Render dashboard, add the following environment variables:

#### Required Variables:
- `SECRET_KEY`: Generate a secure secret key (leave blank to auto-generate)
- `DATABASE_URL`: Automatically provided by Render

#### Email Configuration (Optional but recommended):
- `MAIL_SERVER`: Your SMTP server (e.g., smtp.gmail.com)
- `MAIL_PORT`: SMTP port (e.g., 587)
- `MAIL_USE_TLS`: true
- `MAIL_USERNAME`: Your email username
- `MAIL_PASSWORD`: Your email password/app password
- `MAIL_DEFAULT_SENDER`: Default sender email address

#### Stripe Configuration (Required for payments):
- `STRIPE_PUBLIC_KEY`: Your Stripe publishable key
- `STRIPE_SECRET_KEY`: Your Stripe secret key
- `STRIPE_WEBHOOK_SECRET`: Your Stripe webhook secret

#### Application Configuration:
- `APP_URL`: Your Render app URL (e.g., https://cybrscan.onrender.com)
- `ADMIN_EMAIL`: Administrator email address
- `SUPPORT_EMAIL`: Support email address

### Step 4: Deploy

1. Click "Apply" to start the deployment
2. Render will:
   - Create a PostgreSQL database
   - Install Python dependencies
   - Run database migrations
   - Start the Gunicorn server
3. Wait for the deployment to complete (usually 5-10 minutes)

### Step 5: Access Your Application

Once deployed, you can access your application at the URL provided by Render (e.g., `https://cybrscan.onrender.com`).

## Local Development

### Setup

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd CybrScan_render
   ```

2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Copy `.env.example` to `.env` and configure:
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

5. Initialize the database:
   ```bash
   python init_db.py
   ```

6. Run the development server:
   ```bash
   flask run
   ```

### Running Tests

```bash
pytest
```

## Database Management

### Running Migrations

After making changes to models:

```bash
flask db migrate -m "Description of changes"
flask db upgrade
```

### Backup and Restore

For PostgreSQL on Render:
- Render automatically backs up your database
- You can create manual backups from the Render dashboard

## Troubleshooting

### Common Issues

1. **Database Connection Errors**
   - Ensure DATABASE_URL is properly set
   - Check that PostgreSQL service is running

2. **Email Not Sending**
   - Verify SMTP credentials
   - Check firewall/security settings
   - For Gmail, use App Passwords

3. **Static Files Not Loading**
   - Ensure proper file permissions
   - Check that uploads directory exists

4. **Migration Errors**
   - Delete migrations folder and reinitialize
   - Ensure all model imports are correct

### Logs

View logs in Render dashboard or use Render CLI:
```bash
render logs <service-name>
```

## Security Considerations

1. **Environment Variables**: Never commit `.env` files
2. **Secret Keys**: Use strong, unique secret keys
3. **Database**: Use PostgreSQL for production
4. **HTTPS**: Always use HTTPS in production (Render provides this)
5. **Rate Limiting**: Configured by default
6. **CORS**: Configure allowed origins for production

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests
5. Submit a pull request

## License

[Your License Here]

## Support

For support, email support@cybrscan.com or open an issue on GitHub.