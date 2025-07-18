
from fastapi import FastAPI, Form, File, UploadFile, HTTPException, Request
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import json
import pymysql
import os
from dotenv import load_dotenv
import shutil
import zipfile
import io
import requests
import base64
import cloudinary
import cloudinary.uploader
from pathlib import Path
from pydantic import BaseModel
from urllib.parse import quote
from fastapi.responses import RedirectResponse
from cloudinary.utils import cloudinary_url
from datetime import datetime, timedelta
from functools import partial
import asyncio
import smtplib
from email.message import EmailMessage







app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Change "*" to a specific domain in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


load_dotenv()



SMTP_SERVER = os.getenv('SMTP_SERVER')   # Replace with your SMTP server
SMTP_PORT = os.getenv('SMTP_PORT')                    # Use 465 for SSL, 587 for TLS
SMTP_USER = os.getenv('SMTP_USER')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
cloudinary.config(
    cloud_name= os.getenv('CLOUD_NAME'),
    api_key= os.getenv('API_KEY'),
    api_secret= os.getenv('API_SECRET')
)
def get_db_connection():
    return pymysql.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME"),
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True
    )

class User(BaseModel):
    username: str
    password: str
class rejectt(BaseModel):
    memoId: int
    role: str
    comment: str
class ApprovalData(BaseModel):
    memo_id: int
    role: str
    comment: str
@app.post("/login")
async def login(creds:User):
    conn=get_db_connection()
    cursor=conn.cursor()
    sql = "SELECT * FROM users WHERE username=%s"
    cursor.execute(sql, (creds.username,))
    user = cursor.fetchone()
    
    cursor.close()
    conn.close()

    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    # Plain text password check (replace with hash check in production)
    if creds.password != user["password"]:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    # Remove password before sending response (for security)
    user.pop("password")
    
    # Now 'user' dict includes roles or any other info stored in your users table
    return {"status": "Login successful", "user": user}



@app.post("/upload")
async def upload_file(
    person: str = Form(...),
    department: str = Form(...),
    destination: str = Form(...),
    email: str = Form(...),
    memo: UploadFile = File(...)
):
    try:
        file_bytes = await memo.read(MAX_FILE_SIZE + 1)

        if len(file_bytes) > MAX_FILE_SIZE:
            msg = EmailMessage()
            msg["Subject"] = "📩 Memo Failed To Upload"
            msg["From"] = SMTP_USER
            msg["To"] = email

            html = f"""
            <html>
              <body>
                <p style="font-size:30px"><strong>Hello {person},</strong></p>
                <p style="font-size:16px">Your memo has been rejected because it is too large.</p>
                <p style="font-size:16px">Try uploading a memo that is less than 5MB.</p>
                <p style="font-size:16px"><strong>Best regards,<br>Memo System,<br>By John Ngugi</strong></p>
              </body>
            </html>
            """
            msg.set_content("Your memo is too large. Please upload one under 5MB.")
            msg.add_alternative(html, subtype="html")

            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as smtp:
                smtp.starttls()
                smtp.login(SMTP_USER, SMTP_PASSWORD)
                smtp.send_message(msg)

            return {"message": "❌ Memo is too large. Notification sent to user."}

        # Upload to Cloudinary
        upload_func = partial(
            cloudinary.uploader.upload,
            file_bytes,
            folder="memos",
            type="authenticated"
        )
        upload_result = await asyncio.to_thread(upload_func)

        public_id = upload_result.get("public_id")
        if not public_id:
            raise Exception("Upload failed. No public_id returned.")

        conn = get_db_connection()
        with conn.cursor() as cursor:
            # Save memo to DB
            cursor.execute(
                "INSERT INTO memos (submitted_by, department, destination, email, image_filename) VALUES (%s, %s, %s, %s, %s)",
                (person, department, destination, email, public_id)
            )

            # Notify all departments in the destination list
            try:
                destinations = json.loads(destination) if isinstance(destination, str) else destination
            except json.JSONDecodeError:
                destinations = [destination]  # fallback

            emails_sent = []

            for dept in destinations:
                dept_clean = dept.strip().lower()

                cursor.execute("SELECT email FROM users WHERE LOWER(role) = %s", (dept_clean,))
                dest_result = cursor.fetchone()

                if dest_result and dest_result.get("email"):
                    dest_email = dest_result["email"]

                    image_url = generate_signed_url(public_id)
                    image_response = requests.get(image_url)
                    image_data = base64.b64encode(image_response.content).decode("utf-8")
                    image_extension = image_response.headers.get("Content-Type", "image/jpeg").split("/")[-1]

                    msg = EmailMessage()
                    msg["Subject"] = f"📩 New Memo Submitted to {dept.capitalize()} Department"
                    msg["From"] = SMTP_USER
                    msg["To"] = dest_email

                    html = f"""
                    <html>
                      <body>
                        <p style="font-size:30px"><strong>Hello {dept.capitalize()} Department,</strong></p>
                        <p style="font-size:16px">A new memo has been submitted by <strong>{person}</strong> from <strong>{department}</strong>.</p>
                        <p style="font-size:16px">Please visit the app to see the memo.</p>
                        <p style="font-size:16px"><strong>Best regards,<br>Memo System,<br>By John Ngugi</strong></p>
                      </body>
                    </html>
                    """
                    msg.set_content("A new memo has been submitted. Please check your email client for HTML content.")
                    msg.add_alternative(html, subtype="html")

                    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as smtp:
                        smtp.starttls()
                        smtp.login(SMTP_USER, SMTP_PASSWORD)
                        smtp.send_message(msg)

                    emails_sent.append(dept.capitalize())

        conn.commit()
        conn.close()

        if emails_sent:
            return {
                "message": f"✅ Memo uploaded and email sent to: {', '.join(emails_sent)}.",
                "public_id": public_id
            }
        else:
            return {
                "message": f"⚠️ Memo uploaded, but no email sent — no matching departments found.",
                "public_id": public_id
            }

    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")


def generate_signed_url(public_id: str) -> str:
    url, _ = cloudinary_url(
        public_id,
        type="authenticated",
        resource_type="image",
        sign_url=True,
        secure=True,
        expires_at=(datetime.utcnow() + timedelta(hours=1)).timestamp()
    )
    return url

@app.get("/view")
async def view_memos(request: Request):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM memos")
    rows = cursor.fetchall()
    conn.close()

    memos = []
    for row in rows:
        # ✅ Generate signed URL from public_id
        image_url = generate_signed_url(row['image_filename'])

        def fmt(approved, approved_at, label):
            if approved:
                if approved_at:
                    return f"{label} approved on: {approved_at.strftime('%d/%m/%Y')}"
                return f"{label} approved"
            return f"Pending approval from {label}"

        approval_status = [
            fmt(row['director_approved'], row['director_approved_at'], "Director"),
            fmt(row['hr_approved'], row['hr_approved_at'], "HR"),
            fmt(row['commercial_approved'], row['commercial_approved_at'], "Commercial"),
            fmt(row['accounts_approved'], row['accounts_approved_at'], "Accounts"),
            fmt(row['ict_approved'], row['ict_approved_at'], "Ict"),
            fmt(row['engineering_approved'], row['engineering_approved_at'], "Engineering"),
            
            fmt(row['registry_approved'], row['registry_approved_at'], "Registry")
        ]

        comments = {
            "director": row.get("director_comment"),
            "hr": row.get("hr_comment"),
            "commercial": row.get("commercial_comment"),
            "accounts": row.get("accounts_comment"),
            "ict": row.get("ict_comment"),
            "engineering": row.get("engineering_comment"),
            "registry": row.get("registry_comment")
        }

        memos.append({
            'id': row['id'],
            'submitted_by': row.get('submitted_by', ''),
            'department': row['department'],
            'destination': row['destination'],
            'status': row['status'],
            'image_url': image_url,
            'created_at': row['created_at'].strftime('%d/%m/%Y %H:%M:%S'),
            'approval_status': approval_status,
            'comments': comments  
        })

    return {"status": "OK", "data": memos}
@app.get("/uploads/{filename}")
async def get_uploaded_file(filename: str):
    # Ensure filename is safe for URL
    safe_filename = quote(filename)
    
    # Construct the Cloudinary URL
    cloud_url = f"https://res.cloudinary.com/YOUR_CLOUD_NAME/image/upload/memos/{safe_filename}"

    # Optionally: you could check if file exists on Cloudinary via API (costs time), or trust naming
    return RedirectResponse(url=cloud_url)
@app.post("/approve/director/{memo_id}")
async def approve_director(memo_id: int):
    now = datetime.now()
    conn = get_db_connection()
    with conn.cursor() as cursor:
        cursor.execute(
            """
            UPDATE memos
            SET status = %s,
                director_approved = 1,
                director_approved_at = %s
            WHERE id = %s
            """,
            ("Pending HR Approval", now, memo_id)
        )
    conn.close()
    return {"message": f"Memo {memo_id} approved by Director"}

@app.post("/reject")
async def reject_drop(memo_reject: rejectt):
    memo_id = memo_reject.memoId
    role = memo_reject.role.lower()
    comment=memo_reject.comment
    conn = get_db_connection()
    cursor = conn.cursor()

    # Update status
    approval_column = f"{role}_approved"
    timestamp_column = f"{role}_approved_at"
    message_column = f"{role}_comment"
    new_status = f"{role.capitalize()} rejected"

    cursor.execute(f"""
        UPDATE memos
        SET {approval_column} = 0,
            {timestamp_column} = CURRENT_TIMESTAMP,
            {message_column} = %s,
            status = %s
        WHERE id = %s
    """, (comment, new_status, memo_id))

    # Get email and image public_id
    cursor.execute("SELECT email, image_filename FROM memos WHERE id=%s", (memo_id,))
    result = cursor.fetchone()
    conn.commit()
    conn.close()

    if not result:
        raise HTTPException(status_code=404, detail="Memo not found")

    email = result["email"]
    public_id = result["image_filename"]

    try:
        # Get signed URL and image content
        image_url = generate_signed_url(public_id)
        response = requests.get(image_url)

        if response.status_code != 200:
            raise Exception("Failed to fetch image from Cloudinary")

        image_data = response.content
        image_type = response.headers.get("Content-Type", "image/jpeg").split("/")[-1]

        # Prepare email
        msg = EmailMessage()
        msg['Subject'] = f"📩 Your memo has been rejected by {role.capitalize()}"
        msg['From'] = SMTP_USER
        msg['To'] = email

        # HTML with embedded image via CID
        html = f"""
        <html>
          <body>
            <p style="font-size:30px">Hello,</p>
            <p style="font-size:19px">Your memo has been <span style="color:red;"><strong>rejected</strong></span> by the <strong>{role.capitalize()}</strong> department.</p>
            <p style="font-size:19px">Below is the image of your memo:</p>
            <img src="cid:memoimage" style="max-width:500px; border:1px solid #ccc;" />
            <p style="font-size:19px">Please contact the department for clarification.</p>
            <p style="font-size:19px"><strong>Best regards,<br>Memo Approval System,<br>By John Ngugi</strong></p>
          </body>
        </html>
        """

        msg.set_content("Your memo has been rejected. Please check your email client for the image.")
        msg.add_alternative(html, subtype='html')
        msg.get_payload()[1].add_related(image_data, maintype='image', subtype=image_type, cid='memoimage')

        # Send email
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as smtp:
            smtp.starttls()
            smtp.login(SMTP_USER, SMTP_PASSWORD)
            smtp.send_message(msg)

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to send email: {str(e)}")

    return {"message": f"{role.capitalize()} rejection successful. Notification sent to {email}"}

@app.post("/approve")
async def approve(data: ApprovalData):
    memo_id = data.memo_id
    role = data.role.lower()
    comment=data.comment

    conn = get_db_connection()
    cursor = conn.cursor()

    # Update approval column and status
    approval_column = f"{role}_approved"
    message_column = f"{role}_comment"
    timestamp_column = f"{role}_approved_at"
    new_status = f"{role.capitalize()} approved"

    cursor.execute(f"""
        UPDATE memos
        SET {approval_column} = 1,
            {timestamp_column} = CURRENT_TIMESTAMP,
            {message_column} = %s,
            status = %s
        WHERE id = %s
    """, (comment, new_status, memo_id))

    # Fetch email and image public ID
    cursor.execute("SELECT email, image_filename FROM memos WHERE id=%s", (memo_id,))
    result = cursor.fetchone()
    conn.commit()
    conn.close()

    if not result:
        raise HTTPException(status_code=404, detail="Memo not found")

    email = result["email"]
    public_id = result["image_filename"]

    # Send approval email
    try:
        image_url = generate_signed_url(public_id)
        response = requests.get(image_url)

        if response.status_code != 200:
            raise Exception("Failed to fetch image from Cloudinary")

        image_data = response.content
        image_type = response.headers.get("Content-Type", "image/jpeg").split("/")[-1]

        msg = EmailMessage()
        msg['Subject'] = f"📩 Your memo has been approved by {role.capitalize()}"
        msg['From'] = SMTP_USER
        msg['To'] = email

        html = f"""
        <html>
          <body>
            <p style="font-size:30px"><strong>Hello,</strong></p>
            <p style="font-size:19px">Your memo has been <span style="color:green;"><strong>approved</strong></span> by the <strong>{role.capitalize()}</strong> department.</p>
            <p style="font-size:19px">Below is the image of your memo:</p>
            <img src="cid:memoimage" style="max-width:500px; border:1px solid #ccc;" />
            <p style="font-size:19px">Please contact the department for clarification.</p>
            <p style="font-size:19px"><strong>Best regards,<br>Memo Approval System,<br>By John Ngugi</strong></p>
          </body>
        </html>
        """

        msg.set_content("Your memo has been approved. Please check your email client for the image.")
        msg.add_alternative(html, subtype='html')
        msg.get_payload()[1].add_related(image_data, maintype='image', subtype=image_type, cid='memoimage')

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as smtp:
            smtp.starttls()
            smtp.login(SMTP_USER, SMTP_PASSWORD)
            smtp.send_message(msg)

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to send email: {str(e)}")

    return {"message": f"{role.capitalize()} approval successful. Notification sent to {email}"}

@app.get("/download-all")
async def download_all_images():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT image_filename FROM memos")
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        raise HTTPException(status_code=404, detail="No images found")

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w') as zip_file:
        for row in rows:
            filename = row['image_filename']
            filepath = UPLOAD_FOLDER / filename
            if filepath.is_file():
                zip_file.write(filepath, arcname=filename)

    zip_buffer.seek(0)

    return FileResponse(
        zip_buffer,
        media_type='application/zip',
        filename='all_memos.zip'
    )
