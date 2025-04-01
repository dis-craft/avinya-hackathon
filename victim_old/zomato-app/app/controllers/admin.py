from flask import Blueprint, render_template, request, redirect, url_for, session, jsonify
from app.services.db import get_db_connection
import threading
import os
import json
from datetime import datetime

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/admin')
def admin_dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('auth.login'))
    
    # No proper role checking - any logged-in user can access admin
    # Vulnerable authorization check
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get all users
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    
    # Get all restaurants
    cursor.execute("SELECT * FROM restaurants")
    restaurants = cursor.fetchall()
    
    # Get all orders
    cursor.execute("SELECT * FROM orders")
    orders = cursor.fetchall()
    
    conn.close()
    
    return render_template('admin.html', users=users, restaurants=restaurants, orders=orders)

@admin_bp.route('/api/users')
def api_users():
    # No authentication check for sensitive data
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    conn.close()
    
    return jsonify([dict(row) for row in users])

@admin_bp.route('/api/orders')
def api_orders():
    # No authentication check for sensitive data
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM orders")
    orders = cursor.fetchall()
    conn.close()
    
    return jsonify([dict(row) for row in orders])

@admin_bp.route('/process_order', methods=['POST'])
def process_order():
    if not session.get('logged_in'):
        return redirect(url_for('auth.login'))
    
    order_id = request.form.get('order_id')
    status = request.form.get('status')
    
    if not order_id or not status:
        return "Missing order_id or status", 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE orders SET status = ? WHERE id = ?", (status, order_id))
    conn.commit()
    conn.close()
    
    return redirect(url_for('admin.admin_dashboard')) 