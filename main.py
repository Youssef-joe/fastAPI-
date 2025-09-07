from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import Dict
from schemas import UserCreate, UserOut, Token
import auth
from jose import JWTError

app = FastAPI(title="Task Manager (Learning)")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# In Memory DB
fake_users_db: Dict[str, dict] = {}
_next_id = 1


@app.post("/signup", response_model=UserOut, status_code=201)
def sign_up(user:UserCreate):
    global _next_id
    
    if user.email in fake_users_db:
        raise HTTPException(status_code=400, detail="Email Already Registered")
    hashed = auth.get_password_hash(user.password)
    fake_users_db[user.email] = {"id": _next_id, "email": user.email, "hashed_password": hashed}
    _next_id += 1
    return UserOut(id=fake_users_db[user.email]["id"], email=user.email)


@app.post("/token", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = fake_users_db.get(form_data.username)
    if not user or not auth.verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect Email Or Password")
    access_token = auth.create_access_token({"sub": user["email"]})
    return {"access_token": access_token, "token_type": "bearer"}

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = auth.decode_token(token)
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid Token Payload")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid Token")
    
    user = fake_users_db.get(email)
    if user is None:
        raise HTTPException(status_code=401, detail="User Not Found")
    return user
     
@app.get("/me")
def read_me(current_user: dict = Depends(get_current_user)):
    return {"id": current_user["id"], "email": current_user["email"]}