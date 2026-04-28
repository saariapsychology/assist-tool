import os
import uuid
import tempfile
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from dotenv import load_dotenv
from openai import OpenAI
import soundfile as sf
from sqlalchemy.orm import Session

from database import engine, get_db
import models


load_dotenv(override=True)
import os
models.Base.metadata.create_all(bind=engine)

SECRET_KEY = os.getenv("SECRET_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

print("API KEY LOADED:", OPENAI_API_KEY)

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

client = OpenAI(api_key=OPENAI_API_KEY)

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")



pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


def hash_password(password: str) -> str:
    return pwd_context.hash(password[:72])


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> models.User:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.query(models.User).filter(models.User.username == username).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user




def seed_users(db: Session):
    if db.query(models.User).count() > 0:
        return  # Already seeded

    default_password = hash_password("password")

    users = [
        models.User(
            username="admin",
            hashed_password=default_password,
            role="administrator",
            pi_username=None
        ),
        models.User(
            username="staff",
            hashed_password=default_password,
            role="staff",
            pi_username=None
        ),
        models.User(
            username="student",
            hashed_password=default_password,
            role="student",
            pi_username="staff"
        ),
    ]
    db.add_all(users)
    db.commit()
    print("✅ Default users seeded (username = password for all accounts)")


@app.on_event("startup")
def on_startup():
    db = next(get_db())
    seed_users(db)



@app.get("/")
def serve_login():
    return FileResponse("static/login.html")


@app.get("/chat-page")
def serve_chat():
    return FileResponse("static/index.html")

@app.get("/disclaimer-page")
def serve_disclaimer():
    return FileResponse("static/disclaimer.html")


@app.get("/admin-page")
def serve_admin():
    return FileResponse("static/admin.html")

@app.get("/supervisor-page")
def serve_supervisor():
    return FileResponse("static/supervisor.html")




@app.post("/login")
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    user = db.query(models.User).filter(models.User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    token = create_access_token({"sub": user.username, "role": user.role})
    return {"access_token": token, "token_type": "bearer"}




@app.get("/me")
def get_me(current_user: models.User = Depends(get_current_user)):
    """Returns the current user's username and role — used by the frontend to decide redirect."""
    return {"username": current_user.username, "role": current_user.role}


@app.get("/users")
def list_users(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.role != "administrator":
        raise HTTPException(status_code=403, detail="Admins only")

    users = db.query(models.User).all()
    return [
        {
            "username": u.username,
            "role": u.role,
            "pi_username": u.pi_username
        }
        for u in users
    ]


@app.post("/impersonate/{username}")
def impersonate(
    username: str,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Admin-only: returns a short-lived token that logs in as the target user."""
    if current_user.role != "administrator":
        raise HTTPException(status_code=403, detail="Admins only")

    target = db.query(models.User).filter(models.User.username == username).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    token = create_access_token({"sub": target.username, "role": target.role})
    return {"access_token": token, "token_type": "bearer", "impersonating": target.username}


class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: str                        # "student" | "staff" | "administrator"
    pi_username: Optional[str] = None


@app.post("/users", status_code=201)
def create_user(
    req: CreateUserRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.role != "administrator":
        raise HTTPException(status_code=403, detail="Admins only")

    if db.query(models.User).filter(models.User.username == req.username).first():
        raise HTTPException(status_code=400, detail="Username already exists")

    user = models.User(
        username=req.username,
        hashed_password=hash_password(req.password),
        role=req.role,
        pi_username=req.pi_username
    )
    db.add(user)
    db.commit()
    return {"message": f"User '{req.username}' created"}


class ReassignRequest(BaseModel):
    pi_username: Optional[str] = None


@app.patch("/users/{username}/supervisor")
def reassign_supervisor(
    username: str,
    req: ReassignRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.role != "administrator":
        raise HTTPException(status_code=403, detail="Admins only")

    user = db.query(models.User).filter(models.User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if req.pi_username:
        supervisor = db.query(models.User).filter(models.User.username == req.pi_username).first()
        if not supervisor or supervisor.role != "staff":
            raise HTTPException(status_code=400, detail="Supervisor must be an existing staff user")

    user.pi_username = req.pi_username or None
    db.commit()
    return {"message": f"'{username}' assigned to supervisor '{req.pi_username or 'none'}'"}


@app.delete("/users/{username}")
def delete_user(
    username: str,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.role != "administrator":
        raise HTTPException(status_code=403, detail="Admins only")

    user = db.query(models.User).filter(models.User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    db.delete(user)
    db.commit()
    return {"message": f"User '{username}' deleted"}




class ChatRequest(BaseModel):
    level: str
    user_input: str
    session_id: Optional[str] = None


def build_system_prompt(level: str) -> str:
    return f"""
Student level: {level}
You are an Interactive Patient Simulation Tool designed to help psychology learners in the UK to practice therapeutic skills. 
You will role-play as a client, responding adaptively to the learner’s input based on the principles of motivational interviewing,
reflective listening, and empathy. At the end of the session, provide feedback on the learner’s strengths, areas for improvement, and suggestions for refinement.
Start by offering the learner three scenarios to choose from (1-3). Scenarios should be culturally diverse and adjusted for UK contexts. 
Once the scenario is chosen, engage in a realistic conversation as the client. Respond as a client might in real life, using short, concise 
statements and avoiding overly detailed explanations. Focus on expressing emotions or brief thoughts, rather than offering long explanations.
 Adapt your responses based on the learner’s input and avoid providing direct feedback during the conversation. End the session when the learner types
‘STOP,’ then summarise the interaction and provide feedback.”
only use these links to answer and feedback, and if its beyond the scope of these links just say you can't help and to email psytechoperations@rhul.ac.uk 
https://www.bps.org.uk/guideline/professional-practice-guidelines
https://www.bps.org.uk/guideline/code-ethics-and-conduct
https://www.bps.org.uk/guideline/social-media-guidance
https://www.bps.org.uk/member-microsite/division-clinical-psychology/publications/policy-supervision
https://www.bps.org.uk/guideline/accreditation-doctoral-clinical-psychology
https://www.bps.org.uk/guideline/electronic-records-guidance
https://www.hcpc-uk.org/standards/standards-of-proficiency/practitioner-psychologists/
https://www.hcpc-uk.org/standards/standards-of-conduct-performance-and-ethics/
https://www.hcpc-uk.org/standards/guidance/guidance-on-conduct-and-ethics-for-students/
https://www.hcpc-uk.org/standards/guidance/social-media-guidance/
https://www.hcpc-uk.org/standards/guidance/confidentiality/
https://www.hcpc-uk.org/standards/standards-of-education-and-training/
https://www.legislation.gov.uk/ukpga/2018/12/contents
https://gdpr.eu/
https://www.gov.uk/government/publications/mental-capacity-act-code-of-practice
https://www.nice.org.uk/guidance/ng225
"""


@app.post("/chat")
def chat(
    request: ChatRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.role != "student":
        raise HTTPException(status_code=403, detail="Only students can chat")

   
    if request.session_id is None:
        session = models.ChatSession(
            id=str(uuid.uuid4()),
            owner_username=current_user.username,
            level=request.level
        )
        db.add(session)
        db.commit()
        db.refresh(session)
    else:
        session = db.query(models.ChatSession).filter(
            models.ChatSession.id == request.session_id,
            models.ChatSession.owner_username == current_user.username
        ).first()
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")

    
    history = [
        {"role": msg.role, "content": msg.content}
        for msg in session.messages
    ]

   
    system_prompt = build_system_prompt(request.level)

 
    messages = [
        {"role": "system", "content": system_prompt},
        *history,
        {"role": "user", "content": request.user_input}
    ]

   
    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=messages
        )

        reply = response.choices[0].message.content

        if isinstance(reply, list):
            reply = " ".join([item.get("text", "") for item in reply])

        if not reply:
            reply = "Sorry, I couldn't generate a response."

    except Exception as e:
        print("OpenAI ERROR:", e)
        reply = "There was an error generating a response."


    db.add(models.Message(
        id=str(uuid.uuid4()),
        session_id=session.id,
        role="user",
        content=request.user_input
    ))

    db.add(models.Message(
        id=str(uuid.uuid4()),
        session_id=session.id,
        role="assistant",
        content=reply
    ))

    db.commit()

    return {"session_id": session.id, "reply": reply}



@app.get("/my-students")
def my_students(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.role != "staff":
        raise HTTPException(status_code=403)

    students = db.query(models.User).filter(
        models.User.pi_username == current_user.username
    ).all()

    return {"students": [s.username for s in students]}


@app.get("/student-sessions/{student_username}")
def view_sessions(
    student_username: str,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.role != "staff":
        raise HTTPException(status_code=403)

    student = db.query(models.User).filter(models.User.username == student_username).first()
    if not student or student.pi_username != current_user.username:
        raise HTTPException(status_code=403)

    sessions = db.query(models.ChatSession).filter(
        models.ChatSession.owner_username == student_username
    ).all()

    return [
        {
            "session_id": s.id,
            "level": s.level,
            "created_at": s.created_at.isoformat(),
            "messages": [
                {"role": m.role, "content": m.content, "timestamp": m.created_at.isoformat()}
                for m in s.messages
            ]
        }
        for s in sessions
    ]



@app.post("/speak")
def speak(text: str = Query(...)):
    audio = client.audio.speech.create(
        model="gpt-4o-mini-tts",
        voice="alloy",
        input=text
    )

    temp = tempfile.NamedTemporaryFile(delete=False, suffix=".wav")
    sf.write(temp.name, audio.audio, audio.sample_rate)

    return FileResponse(temp.name, media_type="audio/wav")