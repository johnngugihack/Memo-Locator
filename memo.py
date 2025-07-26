from fastapi import FastAPI, Form, File, UploadFile, HTTPException, Request, Header, Depends
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
import jwt
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

ALGORITHM = "HS256"
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
SECRET_KEY = os.getenv('SECRET_KEY')


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
async def login(creds: User):
    conn = get_db_connection()
    cursor = conn.cursor()  # use dictionary=True if using MySQL connector for easier dict handling

    sql = "SELECT * FROM users WHERE username=%s"
    cursor.execute(sql, (creds.username,))
    user = cursor.fetchone()

    if not user or creds.password != user["password"]:
        cursor.close()
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid username or password")

    # Generate JWT token
    payload = {
        "sub": user["username"],
        "role": user["role"],
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=1)
    }

    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

    # Save token in the database
    update_sql = "UPDATE users SET token=%s WHERE username=%s"
    cursor.execute(update_sql, (token, creds.username))
    conn.commit()

    cursor.close()
    conn.close()

    user.pop("password")
    user["token"] = token

    return {"status": "Login successful", "user": user}


def verify_token(authorization: str = Header(...)):
    try:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer":
            raise HTTPException(status_code=403, detail="Invalid authentication scheme")
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=403, detail="Invalid token")


@app.post("/upload")
async def upload_file(
    destination: str = Form(...),
    memo: UploadFile = File(...),
    token_data: dict = Depends(verify_token)
):
    try:
        print({destination})
        username = token_data["sub"]
        user_role = token_data["role"]

        conn = get_db_connection()
        cursor = conn.cursor(cursor=pymysql.cursors.DictCursor)

        # Get user email
        cursor.execute("SELECT email FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        email = user["email"]

        # Check file size
        file_bytes = await memo.read(MAX_FILE_SIZE + 1)
        if len(file_bytes) > MAX_FILE_SIZE:
            msg = EmailMessage()
            msg["Subject"] = "📩 Memo Upload Failed"
            msg["From"] = SMTP_USER
            msg["To"] = email
            html = f"""
            <html>
              <body>
                <p><strong>Hello {username},</strong></p>
                <p>Your memo was rejected because it exceeds 5MB.</p>
              </body>
            </html>
            """
            msg.set_content("Your memo is too large.")
            msg.add_alternative(html, subtype="html")

            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as smtp:
                smtp.starttls()
                smtp.login(SMTP_USER, SMTP_PASSWORD)
                smtp.send_message(msg)

            return {"message": "❌ Memo too large. Notification sent."}

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
            raise Exception("Upload failed.")

        # Save memo to database
        cursor.execute(
            "INSERT INTO memos (submitted_by, department, destination, email, image_filename) VALUES (%s, %s, %s, %s, %s)",
            (username, user_role, destination, email, public_id)
        )

        # Parse and notify destination departments
        try:
            dept_list = json.loads(destination) if isinstance(destination, str) else destination
        except json.JSONDecodeError:
            dept_list = [destination]

        emails_sent = []

        for dept in dept_list:
            dept_clean = dept.strip().lower()
            cursor.execute("SELECT email FROM users WHERE LOWER(role) = %s", (dept_clean,))
            results = cursor.fetchall()

            for row in results:
                dest_email = row.get("email")
                if not dest_email:
                    continue

                image_url = generate_signed_url(public_id)
                msg = EmailMessage()
                msg["Subject"] = f"📩 New Memo for {dept.title()} Department"
                msg["From"] = SMTP_USER
                msg["To"] = dest_email
                html = f"""
                <html>
                  <body>
                    <p><strong>Hello {dept.title()} Department,</strong></p>
                    <p>A new memo was submitted by <strong>{username}</strong> from <strong>{user_role}</strong>.</p>
                    <p>Please check the system for details.</p>
                  </body>
                </html>
                """
                msg.set_content("A new memo has been submitted.")
                msg.add_alternative(html, subtype="html")

                with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as smtp:
                    smtp.starttls()
                    smtp.login(SMTP_USER, SMTP_PASSWORD)
                    smtp.send_message(msg)

                emails_sent.append(dest_email)

        conn.commit()
        conn.close()

        if emails_sent:
            return {
                "message": f"✅ Memo uploaded and emails sent to: {', '.join(emails_sent)}.",
                "public_id": public_id
            }
        else:
            return {
                "message": "⚠️ Memo uploaded, but no email sent — no matching departments found.",
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

        memo_data = {
            'id': row['id'],
            'submitted_by': row.get('submitted_by', ''),
            'department': row['department'],
            'destination': row['destination'],
            'image_url': image_url,
            'created_at': row['created_at'].strftime('%d/%m/%Y %H:%M:%S'),
            'approval_status': approval_status,
            'comments': comments  
        }

        # ✅ Only include status if it's rejected
        status = row.get('status', '')
        if status and 'rejected' in status.lower():
            memo_data['status'] = status

        memos.append(memo_data)

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
    comment = memo_reject.comment

    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if memo exists and is already rejected
    cursor.execute("SELECT status FROM memos WHERE id = %s", (memo_id,))
    result = cursor.fetchone()

    if not result:
        conn.close()
        return JSONResponse(content={"error": "Memo not found"}, status_code=404)

    current_status = result['status'] if isinstance(result, dict) else result[0]
    if current_status and "rejected" in current_status.lower():
        conn.close()
        return JSONResponse(
            content={"error": f"This memo is already rejected by({current_status})"},
            status_code=400
        )

    # Proceed to reject the memo
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

    # Get user email and image filename
    cursor.execute("SELECT email, image_filename FROM memos WHERE id=%s", (memo_id,))
    result = cursor.fetchone()
    conn.commit()
    conn.close()

    if not result:
        raise HTTPException(status_code=404, detail="Memo found but related email/image missing.")

    email = result["email"]
    public_id = result["image_filename"]

    # Try to send the email
    try:
        image_url = generate_signed_url(public_id)
        response = requests.get(image_url)

        if response.status_code != 200:
            raise Exception("Failed to fetch image from Cloudinary")

        image_data = response.content
        image_type = response.headers.get("Content-Type", "image/jpeg").split("/")[-1]

        msg = EmailMessage()
        msg['Subject'] = f"📩 Your memo has been rejected by {role.capitalize()}"
        msg['From'] = SMTP_USER
        msg['To'] = email

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

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as smtp:
            smtp.starttls()
            smtp.login(SMTP_USER, SMTP_PASSWORD)
            smtp.send_message(msg)

        return {
            "message": f"{role.capitalize()} rejection successful. Notification sent to {email}"
        }

    except Exception as e:
        print(f"Email send failed: {str(e)}")  # Log the error on the server
        return {
            "message": f"{role.capitalize()} rejection saved, but failed to send email.",
            "email_error": str(e)
        }
@app.post("/approve")
async def approve(data: ApprovalData):
    memo_id = data.memo_id
    role = data.role.lower()
    comment = data.comment

    conn = get_db_connection()
    cursor = conn.cursor()

    # Check memo status
    cursor.execute("SELECT status FROM memos WHERE id = %s", (memo_id,))
    result = cursor.fetchone()

    if not result:
        conn.close()
        return JSONResponse(content={"error": "Memo not found"}, status_code=404)

    current_status = result['status'] if isinstance(result, dict) else result[0]
    if 'rejected' in current_status.lower():
        rejected_role = current_status.lower().split(' rejected')[0].strip()
        if role != rejected_role:
            conn.close()
            return JSONResponse(
                content={"error": f"Memo has already been rejected by {rejected_role}, cannot be approved by others."},
                status_code=400
            )

    # Update approval
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

    # Fetch email + image
    cursor.execute("SELECT email, image_filename FROM memos WHERE id=%s", (memo_id,))
    result = cursor.fetchone()
    conn.commit()
    conn.close()

    if not result:
        return JSONResponse(content={"error": "Memo found but missing email/image"}, status_code=404)

    email = result["email"]
    public_id = result["image_filename"]

    try:
        # Prepare image
        image_url = generate_signed_url(public_id)
        response = requests.get(image_url)
        if response.status_code != 200:
            raise Exception("Failed to fetch image from Cloudinary")

        image_data = response.content
        image_type = response.headers.get("Content-Type", "image/jpeg").split("/")[-1]

        # Compose email
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

        # Send email
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as smtp:
            smtp.starttls()
            smtp.login(SMTP_USER, SMTP_PASSWORD)
            smtp.send_message(msg)

        # ✅ SUCCESS response
        return {
            "message": f"{role.capitalize()} approval successful. Notification sent to {email}"
        }

    except Exception as e:
        print(f"Email failed: {e}")
        return {
            "message": f"{role.capitalize()} approval saved, but failed to send email.",
            "email_error": str(e)
        }

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
