"""
Scanner Blueprint
"""

from flask import Blueprint

scanner_bp = Blueprint('scanner', __name__)

from . import routes