import os

import requests
import telebot

TOKEN = os.environ["TELEGRAM_BOT_TOKEN"]
CHAT_ID = str(os.environ["TELEGRAM_CHAT_ID"])
API = os.getenv("MIDDLEWARE_URL", "http://127.0.0.1:5000/api")

bot = telebot.TeleBot(TOKEN)


def allowed(message):
    return str(message.chat.id) == CHAT_ID and message.chat.type == "private"


def post(endpoint, payload):
    try:
        return requests.post(f"{API}/{endpoint}", json=payload, timeout=40)
    except requests.RequestException:
        response = requests.Response()
        response.status_code = 502
        response._content = b'{"error":"Middleware unavailable"}'
        return response


def api_error(response):
    return f"API Error (HTTP {response.status_code}). Kiem tra dich vu tren Ubuntu."


def format_entry(entry):
    return (
        f"{entry.get('original_name')}\n"
        f"{entry.get('original_path', '')}\n"
        f"Trang thai: {entry.get('status')} (chua xac nhan tren Windows)"
    )


@bot.message_handler(commands=["start", "help"])
def help_cmd(m):
    if not allowed(m):
        return

    bot.reply_to(
        m,
        "WAZUH DLP C2 CONSOLE\n"
        "/quarantine agent_id file_path\n"
        "/isolate agent_id\n"
        "/disable agent_id\n"
        "/restore agent_id filename\n"
        "/listquarantine agent_id",
    )


@bot.message_handler(commands=["quarantine"])
def quarantine(m):
    if not allowed(m):
        return

    parts = m.text.split(maxsplit=2)
    if len(parts) < 3:
        return bot.reply_to(m, "Syntax: /quarantine 006 C:\\Users\\Secret.txt")

    response = post("quarantine", {"agent_id": parts[1], "file_path": parts[2]})
    if response.ok:
        bot.reply_to(
            m,
            "Da gui lenh cach ly. Kiem tra tep nguon, C:\\Wazuh_Quarantine va log tren Windows.",
        )
    else:
        bot.reply_to(m, api_error(response))


@bot.message_handler(commands=["isolate"])
def isolate(m):
    if not allowed(m):
        return

    parts = m.text.split()
    if len(parts) < 2:
        return bot.reply_to(m, "Syntax: /isolate 006")

    response = post("isolate", {"agent_id": parts[1]})
    if response.ok:
        bot.reply_to(m, "Network isolation command sent.")
    else:
        bot.reply_to(m, api_error(response))


@bot.message_handler(commands=["disable"])
def disable(m):
    if not allowed(m):
        return

    parts = m.text.split()
    if len(parts) < 2:
        return bot.reply_to(m, "Syntax: /disable 006")

    response = post("disable", {"agent_id": parts[1]})
    if response.ok:
        bot.reply_to(m, "Disable command sent.")
    else:
        bot.reply_to(m, api_error(response))


@bot.message_handler(commands=["restore"])
def restore(m):
    if not allowed(m):
        return

    parts = m.text.split(maxsplit=2)
    if len(parts) < 3:
        return bot.reply_to(m, "Syntax: /restore 006 filename.txt")

    response = post(
        "restore",
        {"agent_id": parts[1], "quarantine_filename": parts[2]},
    )
    if response.ok:
        bot.reply_to(m, "Restore command sent; YARA will re-scan.")
    else:
        bot.reply_to(m, api_error(response))


@bot.message_handler(commands=["listquarantine"])
def listing(m):
    if not allowed(m):
        return

    parts = m.text.split()
    if len(parts) < 2:
        return bot.reply_to(m, "Syntax: /listquarantine 006")

    response = post("list_quarantine", {"agent_id": parts[1]})
    if not response.ok:
        return bot.reply_to(
            m,
            f"Khong doc duoc lich su yeu cau (HTTP {response.status_code}).",
        )

    try:
        files = response.json().get("files", [])
    except ValueError:
        return bot.reply_to(m, "Middleware tra du lieu khong hop le.")

    if not files:
        bot.reply_to(
            m,
            "Chua co yeu cau trong registry. Day khong phai kiem ke thu muc cach ly.",
        )
        return

    bot.reply_to(m, "\n\n".join(format_entry(entry) for entry in files))


if __name__ == "__main__":
    bot.infinity_polling()
