# ad-blocker-browser-backend-

# 🚀 Telegram Private File Storage Bot

<p align="center">
  <img src="https://img.shields.io/badge/Telegram-Bot-blue?style=for-the-badge&logo=telegram">
  <img src="https://img.shields.io/badge/Python-3.10+-yellow?style=for-the-badge&logo=python">
  <img src="https://img.shields.io/badge/PostgreSQL-Database-blue?style=for-the-badge&logo=postgresql">
  <img src="https://img.shields.io/badge/Flask-Webserver-black?style=for-the-badge&logo=flask">
  <img src="https://img.shields.io/badge/Production-Ready-green?style=for-the-badge">
</p>

---

# 📦 Telegram Private File Storage Bot

A powerful **Admin-Only Telegram File Storage Bot** with:

- 🔐 Private uploads  
- 🔗 Token download links  
- 📊 Storage analytics  
- 👥 User tracking  
- 📢 Broadcast system  
- 🗄 PostgreSQL database  

---

# ✨ Features

## 🔐 Admin Only Upload

- Only admin can upload files  
- Files stored in private channel  
- No forward signature  
- Secure token links  

---

## 🔗 Token-Based File Sharing

Example:

```
https://t.me/YourBot?start=TOKEN
```

Anyone with this link can download the file.

---

# 📁 Supported File Types

- 📄 Documents  
- 🖼 Photos  
- 🎥 Videos  
- 🎧 Audio  
- 🎤 Voice  
- 📝 Text Messages  

---

# ⚠️ Important Setup Requirement

The bot **must be added** to a **Telegram Channel or Group**.

## ✅ Supported

- Private Channel  
- Public Channel  
- Private Group  
- Public Group  

---

# 🔐 Required Bot Permissions

Bot **must have full message control**:

Enable these permissions:

- ✅ Post Messages  
- ✅ Edit Messages  
- ✅ Delete Messages  
- ✅ Read Messages  
- ✅ Send Media  
- ✅ Manage Messages  

---

# 📌 Recommended Setup (Best Practice)

Create:

- Private Storage Channel
- Add Bot as Admin
- Disable signatures (optional)

Then set:

```
STORAGE_CHANNEL_ID=-100xxxxxxxxxx
```

---

# 🧠 How It Works

```
Admin Upload
     ↓
Storage Channel
     ↓
Token Generated
     ↓
Share Link
     ↓
User Downloads
```

---

# 📊 Admin Commands

| Command | Description |
|---------|-------------|
| /start | Admin dashboard |
| /stats | Bot statistics |
| /users | List users |
| /broadcast | Broadcast message |
| /cancel_broadcast | Cancel broadcast |
| /mylinks | Recent files |
| /mystats | Personal stats |
| /test | Test channel |

---

# 📢 Broadcast System

Send message to all users:

```
/broadcast
```

Then send message.

Supports:

- Text  
- Files  
- Photos  
- Videos  
- Forwarded Messages  

---

# 🛠 Tech Stack

<p align="center">
<img src="https://skillicons.dev/icons?i=python,postgresql,flask,github,linux" />
</p>

### Built With

- Python  
- python-telegram-bot  
- PostgreSQL  
- Flask  
- Asyncio  

---

# ⚙️ Environment Variables

```
BOT_TOKEN=your_bot_token
ADMIN_ID=your_telegram_id
DATABASE_URL=postgres_url
STORAGE_CHANNEL_ID=channel_id
RENDER_EXTERNAL_URL=render_url
```

---

# 🗄 Database Structure

## Users Table

- user_id  
- username  
- first_name  
- joined_date  
- total_files  
- total_size  
- welcome_sent  

---

## Files Table

- file_id  
- file_name  
- file_size  
- token  
- message_id  
- link  

---

# 🚀 Deployment

Supports:

- Render  
- Railway  
- VPS  
- Docker  

---

# ▶️ Run Locally

```
pip install python-telegram-bot flask psycopg
```

Run:

```
python bot.py
```

---

# 📈 Example

Upload file

Bot reply:

```
File stored successfully

Name: file.pdf
Size: 3.2 MB

Link:
https://t.me/YourBot?start=TOKEN
```

---

# 🔒 Security

- Admin-only uploads  
- Secure token links  
- Private storage channel  
- PostgreSQL metadata  

---

# 🔮 Future Features

- Premium users  
- File search  
- Expiring links  
- Web dashboard  
- Download counter  

---

# ⭐ Production Ready

This bot is:

- Scalable  
- Secure  
- Fast  
- Production Ready  

---

# ❤️ Support

If you like this project:

- ⭐ Star repo  
- 🍴 Fork project  
- 🔧 Contribute  

---

# 📜 License

MIT License

---

# 👨‍💻 Author

Telegram Private File Storage Bot

---

# 🚀 Ready For Deployment