# ─── AUTO INIT DB ON STARTUP ────────────────────────
with app.app_context():
    try:
        db.create_all()
        if not Admin.query.first():
            admin = Admin(
                username=Config.ADMIN_USERNAME,
                password_hash=generate_password_hash(Config.ADMIN_PASSWORD)
            )
            db.session.add(admin)
            db.session.commit()
            print(f"[ONEX] Admin created successfully: {Config.ADMIN_USERNAME}")
    except Exception as e:
        print(f"[ONEX] DB Init Error: {e}")

# ─── RUN ─────────────────────────────────────────────
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
