import asyncio
from easyproto import Client

async def main():
    tg = Client.from_env()

    @tg.on_message(pattern=r"^/ping$", incoming=False)
    async def ping(event):
        # Reply only to messages from your own account (e.g. Saved Messages).
        if event.sender_id == (await tg.me()).id:
            await event.reply("pong")

    async with tg:
        await tg.listen()

if __name__ == "__main__":
    asyncio.run(main())
