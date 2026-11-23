from getpass import getpass

import requests


def private_chat_ids(updates):
    chats = set()

    for update in updates:
        message = update.get("message", {})
        chat = message.get("chat", {})
        if chat.get("type") == "private":
            chats.add(str(chat["id"]))

    return chats


def main():
    token = getpass("Bot token (hidden input): ").strip()

    try:
        response = requests.get(
            f"https://api.telegram.org/bot{token}/getUpdates",
            timeout=20,
        )
        data = response.json()

        if not response.ok or not data.get("ok"):
            print("Cannot read updates. Check token, webhook and other polling sessions.")
            return 1

        chats = private_chat_ids(data.get("result", []))

        if not chats:
            print("No private chat found. Send /start to your bot, then retry.")

        for chat_id in sorted(chats):
            print("Private chat ID:", chat_id)

        return 0
    except (requests.RequestException, ValueError):
        print("Unable to read Telegram updates. Token was not logged.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
