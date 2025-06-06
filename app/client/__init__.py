"""
Client Blueprint for CybrScan
"""

from flask import Blueprint

client_bp = Blueprint('client', __name__, template_folder='../../templates/client')

from . import routes