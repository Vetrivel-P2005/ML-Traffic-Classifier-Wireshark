from twilio.rest import Client as TwilioClient

def send_sms(summary, to_number, from_number, account_sid, auth_token):
    client = TwilioClient(account_sid, auth_token)
    message = client.messages.create(
        body=summary,
        from_=from_number,
        to=to_number
    )
    return message.sid

if __name__ == "__main__":
    

    # --- Twilio details ---
    ACCOUNT_SID = ""
    AUTH_TOKEN = ""
    FROM_NUMBER = ""   # Twilio number
    TO_NUMBER = "+919042213566"   # Your mobile number

    

    # Step 2: Summarize with LLM
    summary = "Hi Vetri i am vetri"
    

    # Step 3: Send SMS
    sms_id = send_sms(summary, TO_NUMBER, FROM_NUMBER, ACCOUNT_SID, AUTH_TOKEN)
    print("SMS Sent! SID:", sms_id)
