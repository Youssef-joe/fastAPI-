from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import Dict
from schemas import UserCreate, UserOut, Token
import auth
from jose import JWTError
from sqlalchemy.orm import Session
from database import session_local, engine, Base
from models import User

app = FastAPI(title="Task Manager (Learning)")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# SQL_lite DB
Base.metadata.create_all(Bind=engine)

# Dependency: Get DB session
def get_db():
    db = session_local()
    try:
        yield db
    finally: 
        db.close()



@app.post("/signup", response_model=UserOut, status_code=201)
def sign_up(user:UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email Already Registered")
    
    hashed_pw = auth.get_password_hash(user.password)
    new_user = User(email= user.email, hashed_password=hashed_pw)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return UserOut(id=new_user.id, email=new_user.email)


@app.post("/token", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db:Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not auth.verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect Email Or Password")
    access_token = auth.create_access_token({"sub": user["email"]})
    return {"access_token": access_token, "token_type": "bearer"}

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = auth.decode_token(token)
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid Token Payload")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid Token")
    
    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise HTTPException(status_code=401, detail="User Not Found")
    return user
     
@app.get("/me")
def read_me(current_user: User = Depends(get_current_user)):
    return {"id": current_user["id"], "email": current_user["email"]}