import logging
from fastapi import FastAPI, Depends, HTTPException, status
from pydantic import BaseModel
from typing import List, Generator
from sqlalchemy import create_engine, Column, Integer, String, sql
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from enum import Enum
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import requests
import os

SECRET_KEY = os.environ['APP_JWT_SECRET']
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

db_user = os.environ['POSTGRES_USER']
db_pass = os.environ['POSTGRES_PASSWORD']
db_name = os.environ['APP_DB']

admin_user = os.environ['APP_ADMIN_USER']
admin_pass = os.environ['APP_ADMIN_PASS']

DATABASE_URL = f"postgresql://{db_user}:{db_pass}@database:5432/{db_name}"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class Role(str, Enum):
    user = "user"
    admin = "admin"

class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default=Role.user.value)

Base.metadata.create_all(bind=engine)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def create_admin_user():
    global admin_user, admin_pass
    db = SessionLocal()
    existing_admin = db.query(User).filter(User.username == admin_user).first()
    if not existing_admin:
        hashed_password = get_password_hash(admin_pass)
        admin_user = User(username=admin_user, hashed_password=hashed_password, role=Role.admin.value)
        db.add(admin_user)
        db.commit()
        logger.info(f"Admin user created: {admin_user.username}")
    db.close()

create_admin_user()

app = FastAPI()

# Схемы Pydantic
class RoleEnum(str, Enum):
    user = "user"
    admin = "admin"

class UserCreate(BaseModel):
    username: str
    password: str

class UserOut(BaseModel):
    id: int
    username: str
    role: RoleEnum

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str
    
def get_db() -> Generator:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Не удалось подтвердить учетные данные",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            logger.warning("Token payload did not contain a username.")
            raise credentials_exception
    except JWTError as e:
        logger.error(f"JWT decode error: {e}")
        raise credentials_exception
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        logger.warning("User not found in database.")
        raise credentials_exception
    logger.info(f"Authenticated user: {user.username}")
    return user

def get_current_admin_user(current_user: User = Depends(get_current_user)):
    if current_user.role != Role.admin.value:
        logger.warning(f"User {current_user.username} attempted admin access without permission.")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Недостаточно прав для выполнения этого действия",
        )
    return current_user

@app.post("/register", response_model=UserOut)
def register(user: UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.username == user.username).first()
    if existing_user:
        logger.info(f"Attempt to register existing username: {user.username}")
        raise HTTPException(status_code=400, detail="Пользователь уже существует")
    hashed_password = get_password_hash(user.password)
    new_user = User(username=user.username, hashed_password=hashed_password, role=Role.user.value)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    logger.info(f"New user registered: {new_user.username}")
    return new_user

@app.post("/token", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        logger.warning(f"Failed login attempt for username: {form_data.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Некорректный логин или пароль",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(
        data={"sub": user.username},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    logger.info(f"User logged in: {user.username}")
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/health-check")
def health_check(db: Session = Depends(get_db)):
    try:
        db.execute(sql.text("SELECT 1"))
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=503, detail="Service unavailable")
    logger.info("Health check passed.")
    return {"status": "ok"}

@app.get("/users", response_model=List[UserOut])
def get_users(current_user: User = Depends(get_current_admin_user), db: Session = Depends(get_db)):
    users = db.query(User).all()
    logger.info("Admin accessed users list.")
    return users

@app.get("/user/{user_id}", response_model=UserOut)
def get_user(user_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        logger.warning(f"User with ID {user_id} not found.")
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    if current_user.role != Role.admin.value and current_user.id != user.id:
        logger.warning(f"User {current_user.username} attempted to access another user's data without permission.")
        raise HTTPException(status_code=403, detail="Недостаточно прав для просмотра этого пользователя")
    logger.info(f"User {current_user.username} accessed data for user {user.username}.")
    return user

@app.delete("/user/{user_id}", status_code=204)
def delete_user(user_id: int, current_user: User = Depends(get_current_admin_user), db: Session = Depends(get_db)):
    user_to_delete = db.query(User).filter(User.id == user_id).first()
    if user_to_delete is None:
        logger.warning(f"User with ID {user_id} not found for deletion.")
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    db.delete(user_to_delete)
    db.commit()
    logger.info(f"User {user_to_delete.username} (ID: {user_to_delete.id}) was deleted by admin {current_user.username}.")
    return

@app.get("/weather/{city}")
def get_weather(city: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    url = f"http://weather-srv:8000/{city}"
    response = requests.get(url)
    if response.status_code != 200:
        logger.error(f"Failed to retrieve weather data for {city}")
        raise HTTPException(status_code=500, detail="Error fetching weather data")
    logger.info(f"Weather data retrieved for city: {city}")
    return response.json()
