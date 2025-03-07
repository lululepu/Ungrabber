import re

TelegramToken = re.compile(r'\d+:[a-zA-Z\d_-]+\$(?:-)?\d+')

DiscordWebhook = re.compile(r'https:\/\/(?:canary\.)?(?:ptb\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+')
CanaryB64Webhook = re.compile(r'aHR0cHM6Ly9jYW5hcnkuZGlzY29yZC5jb20vYXBpL3dlYmhvb2tz[a-zA-Z\d]+(?:={1,2})?')
DiscordAppB64Webhook = re.compile(r'aHR0cHM6Ly9kaXNjb3JkYXBwLmNvbS9hcGkvd2ViaG9va3M[a-zA-Z\d]+(?:={1,2})?')
DiscordB64Webhook = re.compile(r'aHR0cHM6Ly9kaXNjb3JkLmNvbS9hcGkvd2ViaG9va3Mv[a-zA-Z\d]+(?:={1,2})?')
PTBB64Webhook = re.compile(r'aHR0cHM6Ly9wdGIuZGlzY29yZC5jb20vYXBpL3dlYmhvb2tz[a-zA-Z\d]+(?:={1,2})?')
