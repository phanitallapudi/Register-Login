from fastapi import FastAPI
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional
from fastapi import FastAPI, HTTPException, Depends, Request, status
from pydantic import BaseModel, EmailStr, field_validator, Field
from pydantic.class_validators import validator
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer
from fastapi.security import OAuth2PasswordRequestForm
from pymongo import MongoClient
from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt
from dotenv import load_dotenv

import os
import re

load_dotenv()

username = os.getenv("MONGO_USERNAME")
password = os.getenv("MONGO_PASSWORD")
cluster_name = os.getenv("MONGO_CLUSTER_NAME")
cluster_address = os.getenv("MONGO_CLUSTER_ADDRESS")

mongodb_uri = f"mongodb+srv://{username}:{password}@{cluster_address}/?retryWrites=true&w=majority&appName={cluster_name}"
port = 8000

client = MongoClient(mongodb_uri, port)

db = client["Login_DB"]

user_data = db["users"]

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 360

pwd_cxt = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

class Hash():
    def bcrypt(password: str):
        return pwd_cxt.hash(password)
    
    def verify(hashed, normal):
        return pwd_cxt.verify(normal, hashed)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str, credentials_exception):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        print(payload)
        return payload
    except JWTError:
        raise credentials_exception
    
def get_current_user(token: str = Depends(oauth2_scheme)):
	credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
	return verify_token(token,credentials_exception)

class TokenData(BaseModel):
    username: Optional[str] = None

class User(BaseModel):
    name: str
    company_name: str
    designation: str
    official_email: EmailStr
    password: str
    confirm_password: str

    @validator("official_email")
    def validate_official_email(cls, v):
        business_email_pattern = r'^[a-zA-Z0-9._%+-]+@(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$'
        if not re.match(business_email_pattern, v):
            raise ValueError("Invalid email format")

        free_email_providers = [
            "gmail.com",
            "yahoo.com",
            "outlook.com",
            "hotmail.com",
            "aol.com",
            "zoho.com",
            "protonmail.com",
            "icloud.com",
            "gmx.com",
            "yandex.com",
            "mail.com",
            "tutanota.com",
            "lycos.com",
            "fastmail.com",
            "hushmail.com",
            "mailfence.com",
            "inbox.com",
            "rediffmail.com",
            "runbox.com",
            "mailbox.org",
            "posteo.net",
            "openmailbox.org"
        ]
        domain = v.split('@')[1]
        if domain in free_email_providers:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, 
                detail="Business email required, free email addresses are not allowed"
            )
        
        return v
    
    @validator("password")
    def validate_password_strength(cls, v):
        password_pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
        if not re.match(password_pattern, v):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password must be at least 8 characters long, include an uppercase letter, a lowercase letter, a number, and a special character"
            )        
        return v

    @validator("confirm_password")
    def passwords_match(cls, v, values, **kwargs):
        password = values.get('password')
        if password and v != password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Passwords do not match"
            ) 
        return v

    @validator("name", "company_name", "designation")
    def not_empty(cls, v):
        if not v.strip():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Fields cannot be empty"
            ) 
        return v

class Login(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

async def authorize_user(current_user: str = Depends(get_current_user)):
    if current_user.get('role') != 'user':
        raise HTTPException(status_code=403, detail="Permission denied")
    return current_user


app = FastAPI(
    title="Login",
    swagger_ui_parameters={"syntaxHighlight": False}
    )

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post('/register')
def create_user(request: User):
    existing_user = db["users"].find_one({"official_email": request.official_email})
    if existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"User {request.official_email} already exists")
    
    hashed_pass = Hash.bcrypt(request.password)
    user_object = dict(request)
    user_object["password"] = hashed_pass
    user_object["confirm_password"] = hashed_pass
    user_object["role"] = "user"
    user_object["expiry"] = datetime.now() + timedelta(days=3)

    user_id = user_data.insert_one(user_object)

    if user_id:
        respone = {"message": "User created successfully"}
        return JSONResponse(content=respone, status_code=status.HTTP_201_CREATED)

    response = {"message": "Failed to create user"}
    return JSONResponse(content=respone, status_code=status.HTTP_400_BAD_REQUEST)


@app.post('/login')
def login(request: OAuth2PasswordRequestForm = Depends()):
    user = user_data.find_one({"official_email": request.username})
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f'No user found with this {request.username} email')
    
    if not Hash.verify(user["password"], request.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid password')
    
    # Get the user's role
    user_role = user.get("role")
    expiry = user.get("expiry")

    if expiry < datetime.now():
        #user_data.delete_one({"official_email": request.username})
        raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Account credentials expired, please create a new one."
            )  


    # Create the access token with the user's role
    access_token = create_access_token(data={"sub": user["official_email"], "role": user_role})
    
    response = {"access_token": access_token, "token_type": "bearer"}
    return JSONResponse(content=response, status_code=status.HTTP_200_OK)

@app.post("/test_creds", dependencies=[Depends(authorize_user)])
async def test_creds(current_user: User = Depends(get_current_user), token: str = Depends(oauth2_scheme)):
    response = {"message": True}
    return JSONResponse(content=response, status_code=200)

@app.get("/")
async def root():
    return RedirectResponse(url="/docs")