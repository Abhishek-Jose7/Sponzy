@app.route('/mark_all_notifications_read')
@login_required
def mark_all_notifications_read():
    Notification.query.filter_by(user_id=current_user.id).update({'is_read': True})
    db.session.commit()
    return redirect(url_for('notifications'))
