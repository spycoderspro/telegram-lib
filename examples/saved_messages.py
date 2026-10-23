import asyncio
from easyproto import Client

async def main():
    async with Client.from_env() as tg:
        message = await tg.send("me", "Hello from EasyProto!")
        await tg.edit("me", message.id, "My first MTProto action")
        async for item in tg.history("me", limit=5):
            print(item.id, item.text)

if __name__ == "__main__":
    asyncio.run(main())
