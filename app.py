# ─── SUBSCRIPTION (SMART DUAL ROUTE) ────────────────
@app.route('/sub/<token>')
def subscription(token):
    user = User.query.filter_by(sub_token=token).first_or_404()
    
    # گرفتن دامنه ریلوی از روی درخواست
    domain = request.host.split(':')[0]
    
    # لیست برنامه‌های V2Ray برای تشخیص
    user_agent = request.headers.get('User-Agent', '').lower()
    accept_header = request.headers.get('Accept', '').lower()
    
    v2ray_clients = [
        'v2ray', 'v2rayng', 'shadowrocket', 'streisand', 'clash',
        'sing-box', 'neko', 'quantumult', 'stash', 'surfboard',
        'foxray', 'passwall', 'hiddify', 'subconverter', 'go-http-client'
    ]
    
    is_v2ray_client = any(client in user_agent for client in v2ray_clients)
    is_browser = 'text/html' in accept_header or ('mozilla' in user_agent and not is_v2ray_client)

    # ۱. اگر درخواست از مرورگر بود -> صفحه گرافیکی را نشان بده
    if is_browser and not is_v2ray_client:
        config_link = generate_config(user, domain)
        sub_link = f"{request.url_root}sub/{user.sub_token}"
        return render_template('sub.html', user=user, config_link=config_link, sub_link=sub_link)

    # ۲. اگر درخواست از برنامه‌های V2Ray بود -> کدهای Base64 ساب‌لینک را بده
    if user.status != 'فعال':
        return Response(
            base64.b64encode(b'# ONEX - Account Expired or Disabled').decode(),
            content_type='text/plain; charset=utf-8'
        )

    content = generate_subscription_content(user, domain)
    response = Response(content, content_type='text/plain; charset=utf-8')
    response.headers['Subscription-Userinfo'] = (
        f"upload={user.upload}; "
        f"download={user.download}; "
        f"total={user.data_limit}; "
        f"expire={int(user.expire_date.timestamp()) if user.expire_date else 0}"
    )
    response.headers['Profile-Title'] = f"ONEX | {user.username}"
    response.headers['Profile-Update-Interval'] = '1'
    response.headers['Support-URL'] = Config.TELEGRAM_CHANNEL_URL
    return response


@app.route('/sub/info/<token>')
def sub_info(token):
    # ریدایرکت خودکار به لینک ساب اصلی
    return redirect(url_for('subscription', token=token))
