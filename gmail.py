import os
import base64
import json
from email.message import EmailMessage
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
import aiohttp
import aiofiles
import asyncio
import re
from openai import OpenAI


SCOPES = ['https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/gmail.send']
MSG_ID = []

class Gmail:
    def __init__(self, session):
        self.session = session
        self.CREDENTIALS_FILE = 'gmail/auth.json'
        self.TOKEN_FILE = 'gmail/token.json'

    async def send_email(self, to, response):
        creds = await self.authenticate_gmail()
        try:
            # create gmail api client
            service = build("gmail", "v1", credentials=creds)
            message = EmailMessage()
            message.set_content(response)
            message["To"] = to
            message["From"] = "merlin228mordor@gmail.com"
            message["Subject"] = "AI response"

            # encoded message
            encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
            create_message = {"raw": encoded_message}

            sent_message = service.users().messages().send(userId="me", body=create_message).execute()
            print(f"Message Id: {sent_message['id']} sent successfully.")
        except Exception as error:
            print(f"An error occurred: {error}")

    async def authenticate_gmail(self):
        creds = None
        if os.path.exists(self.TOKEN_FILE):
            async with aiofiles.open(self.TOKEN_FILE, 'r') as token:
                token_data = await token.read()
                creds = Credentials.from_authorized_user_info(json.loads(token_data), SCOPES)

        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(self.CREDENTIALS_FILE, SCOPES)
                creds = flow.run_local_server(port=0)
            async with aiofiles.open(self.TOKEN_FILE, 'w') as token:
                await token.write(creds.to_json())
        return creds

    async def get_msg_details(self, msg_id, headers):
        url = f'https://gmail.googleapis.com/gmail/v1/users/me/messages/{msg_id}'
        async with self.session.get(url, headers=headers) as response:
            message = await response.json()
            payload = message.get('payload', {})
            headers_list = payload.get('headers', [])

            subject = ''
            from_email = ''
            for header in headers_list:
                if header['name'] == 'Subject':
                    subject = header['value']
                if header['name'] == 'From':
                    from_email = header['value']

            body = ''
            if 'parts' in payload:
                for part in payload['parts']:
                    if part['mimeType'] == 'text/plain':
                        body = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
            else:
                body = base64.urlsafe_b64decode(payload['body']['data']).decode('utf-8')

            return {'from': from_email, 'subject': subject, 'body': body}

    async def check_email(self):
        creds = await self.authenticate_gmail()
        url = 'https://gmail.googleapis.com/gmail/v1/users/me/messages'
        params = {'q': 'in:inbox', 'maxResults': 1}
        headers = {'Authorization': f'Bearer {creds.token}'}

        async with self.session.get(url, headers=headers, params=params) as response:
            data = await response.json()
            messages = data.get('messages', [])
            if not messages:
                print("No new messages.")
                return

            msg_id = messages[0]['id']
            if msg_id in MSG_ID:
                return

            MSG_ID.append(msg_id)
            msg_details = await self.get_msg_details(msg_id, headers)
            email_pattern = r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'
            emails = re.findall(email_pattern, msg_details['from'])
            print(f"Subject: {msg_details['subject']}\n{msg_details['body']}\nMessage ID: {msg_id}\nFrom: {emails[0]}")

            api = "API_KEY"
            openai = OpenAI(api_key=api)
            try:
                # file = openai.files.create(
                #     file=open("asortyment.txt", "rb"),
                # )
                # assistent = openai.beta.assistants.create(
                #     messages=[
                #         {
                #             "name": "AI call-center",
                #             "description": "AI call-center",
                #             "model": "gpt-4o",
                #             "tools": [{"type": "retrieval"}],
                #             "file_ids": [file.id]
                #         }
                #     ]
                # )
                # thread = openai.beta.threads.create(
                #     messages=[
                #         {
                #             "role": "user",
                #             "content": msg_details['body'],
                #         }
                #     ]
                # )
                # text = chat.choices[0].message.content
                # print(f"AI response: {text}")
                # print("Sending email...")
                chat_completion = openai.chat.completions.create(
                messages=[
                    {
                        "role": "user",
                        "content": msg_details['body'],
                    }
                ],
                model="gpt-4o",
            )
                text = chat_completion.choices[0].message.content
                await self.send_email(emails[0], response=text)
            except Exception as e:
                print(f"An error occurred while getting AI response: {e}")

async def main():
    async with aiohttp.ClientSession() as session:
        gmail = Gmail(session)
        while True:
            await gmail.check_email()  

if __name__ == "__main__":
    asyncio.run(main())
