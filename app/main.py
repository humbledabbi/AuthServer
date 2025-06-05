from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from .users import create_user, authenticate_user
from .auth import create_access_token, ACCESS_TOKEN_EXPIRE_MINUTES, decode_access_token
from datetime import timedelta
from fastapi.security import OAuth2PasswordBearer

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="signin")


class SignupModel(BaseModel):
    username: str
    password: str


class SigninModel(BaseModel):
    username: str
    password: str


@app.post("/signup")
def signup(user: SignupModel):
    result = create_user(user)
    if not result:
        raise HTTPException(status_code=400, detail="Username already exists")
    return {"message": f"User '{user.username}' created successfully."}


@app.post("/signin")
def signin(user: SigninModel):
    auth_user = authenticate_user(user.username, user.password)
    if not auth_user:
        raise HTTPException(status_code=401, detail="Invalid username or password - Warning Hack attempt")

    token = create_access_token(
        data={"sub": auth_user.username},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": token, "token_type": "bearer"}


@app.get("/protected")
def read_protected(token: str = Depends(oauth2_scheme)):
    try:
        payload = decode_access_token(token)
        username = payload.get("sub")
        return {"message": f"Hello, {username}! This is a protected route."}
    except:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
