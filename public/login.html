
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ONEX | ورود به پنل</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css" rel="stylesheet">
  <style>
    body { font-family: 'Vazirmatn', sans-serif; }
    .glass-box { background: rgba(15, 23, 42, 0.7); backdrop-filter: blur(20px); border: 1px solid rgba(255, 255, 255, 0.08); }
  </style>
</head>
<body class="bg-[#040711] min-h-screen flex items-center justify-center p-4">

  <div class="w-full max-w-md">
    <!-- Header Logo -->
    <div class="text-center mb-8 flex flex-col items-center">
      <svg class="w-20 h-20 mb-3 drop-shadow-[0_0_15px_rgba(34,211,238,0.5)]" viewBox="0 0 100 100" fill="none">
        <defs>
          <linearGradient id="onexG" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stop-color="#22d3ee"/>
            <stop offset="50%" stop-color="#3b82f6"/>
            <stop offset="100%" stop-color="#a855f7"/>
          </linearGradient>
        </defs>
        <rect x="6" y="6" width="88" height="88" rx="26" fill="#0b1120" stroke="url(#onexG)" stroke-width="2.5"/>
        <circle cx="50" cy="50" r="26" stroke="url(#onexG)" stroke-width="4.5" stroke-dasharray="115 35"/>
        <path d="M39 39L61 61M61 39L39 61" stroke="url(#onexG)" stroke-width="4.5" stroke-linecap="round"/>
        <circle cx="50" cy="50" r="3.5" fill="#22d3ee"/>
      </svg>
      <h1 class="text-3xl font-black text-white tracking-wider">ON<span class="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-purple-400">EX</span></h1>
      <p class="text-xs text-slate-400 mt-1">پنل مدیریت اشتراک V2Ray</p>
    </div>

    <!-- Login Box -->
    <div class="glass-box rounded-3xl p-7 shadow-2xl">
      <h2 class="text-base font-bold text-white mb-5">ورود به حساب کاربری</h2>

      <form id="loginForm" class="space-y-4">
        <div>
          <label class="text-xs text-slate-400 block mb-1.5">نام کاربری</label>
          <input type="text" id="username" value="admin" required class="w-full bg-slate-900 border border-slate-800 rounded-xl px-4 py-3 text-sm text-white outline-none focus:border-cyan-500">
        </div>
        <div>
          <label class="text-xs text-slate-400 block mb-1.5">رمز عبور</label>
          <input type="password" id="password" value="admin123" required class="w-full bg-slate-900 border border-slate-800 rounded-xl px-4 py-3 text-sm text-white outline-none focus:border-cyan-500">
        </div>

        <div id="errMsg" class="hidden text-xs text-rose-400 bg-rose-500/10 border border-rose-500/20 rounded-xl p-3"></div>

        <button type="submit" class="w-full bg-gradient-to-r from-cyan-500 via-blue-500 to-purple-600 text-white font-bold py-3.5 rounded-xl cursor-pointer">
          ورود به داشبورد
        </button>
      </form>

      <a href="https://t.me/V2rayTun0" target="_blank" class="mt-6 flex items-center justify-center gap-2 w-full bg-slate-900 border border-slate-800 py-3 rounded-2xl text-xs text-slate-300 hover:border-[#0088cc]/50">
        📢 عضویت در کانال تلگرام <span class="font-bold text-[#0088cc]">@V2rayTun0</span>
      </a>
    </div>

    <div class="text-center mt-6 text-[11px] text-slate-500">
      توسعه‌دهنده: <a href="https://t.me/Mehtif" target="_blank" class="text-cyan-400 font-bold">@Mehtif</a>
    </div>
  </div>

  <script>
    document.getElementById('loginForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const errEl = document.getElementById('errMsg');
      errEl.classList.add('hidden');
      try {
        const res = await fetch('/api/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            username: document.getElementById('username').value.trim(),
            password: document.getElementById('password').value
          })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error);
        window.location.href = `/dashboard/${data.token}`;
      } catch (err) {
        errEl.textContent = err.message;
        errEl.classList.remove('hidden');
      }
    });
  </script>
</body>
</html>
