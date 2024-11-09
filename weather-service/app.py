import logging
from fastapi import FastAPI, HTTPException, Depends
from sqlalchemy import Column, String, Float, Integer, DateTime, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel
from datetime import datetime, timedelta
import requests
import os

app = FastAPI()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

OPENWEATHER_API_KEY = os.getenv("OPENWEATHER_API_KEY")

db_user = os.environ['POSTGRES_USER']
db_pass = os.environ['POSTGRES_PASSWORD']
db_name = os.environ['WEATHER_DB']

DATABASE_URL = f"postgresql://{db_user}:{db_pass}@database:5432/{db_name}"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class WeatherCache(Base):
    __tablename__ = "weather_cache"

    city = Column(String, primary_key=True, index=True)
    temperature = Column(Float)
    description = Column(String)
    humidity = Column(Integer)
    wind_speed = Column(Float)
    timestamp = Column(DateTime)

class WeatherResponse(BaseModel):
    city: str
    temperature: float
    description: str
    humidity: int
    wind_speed: float

    class Config:
        from_attributes = True

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

async def fetch_weather_from_api(city: str) -> WeatherResponse:
    """Fetch weather data from OpenWeatherMap API."""
    logger.info(f"Fetching weather data from API for city: {city}")
    url = f"http://api.openweathermap.org/data/2.5/weather?q={city}&appid={OPENWEATHER_API_KEY}&units=metric"
    response = requests.get(url)
    if response.status_code != 200:
        logger.error(f"API request failed with status code {response.status_code} for city: {city}")
        raise HTTPException(status_code=response.status_code, detail="City not found or API error")

    data = response.json()
    logger.info(f"Weather data fetched successfully from API for city: {city}")
    return WeatherResponse(
        city=data["name"],
        temperature=data["main"]["temp"],
        description=data["weather"][0]["description"],
        humidity=data["main"]["humidity"],
        wind_speed=data["wind"]["speed"],
    )

async def get_cached_weather(db: Session, city: str):
    """Retrieve weather data from cache if it's not expired."""
    logger.info(f"Checking cache for city: {city}")
    cached_weather = db.query(WeatherCache).filter(WeatherCache.city == city).first()
    if cached_weather:
        if datetime.now() - cached_weather.timestamp < timedelta(minutes=10):
            logger.info(f"Cache hit for city: {city}")
            return cached_weather
        else:
            logger.info(f"Cache expired for city: {city}")
    else:
        logger.info(f"No cache entry found for city: {city}")
    return None

async def update_cache(db: Session, city: str, weather_data: WeatherResponse):
    """Insert or update the cache with fresh weather data."""
    logger.info(f"Updating cache for city: {city}")
    weather_cache = db.query(WeatherCache).filter(WeatherCache.city == city).first()
    if weather_cache:
        weather_cache.temperature = weather_data.temperature
        weather_cache.description = weather_data.description
        weather_cache.humidity = weather_data.humidity
        weather_cache.wind_speed = weather_data.wind_speed
        weather_cache.timestamp = datetime.now()
        logger.info(f"Cache updated for city: {city}")
    else:
        weather_cache = WeatherCache(
            city=city,
            temperature=weather_data.temperature,
            description=weather_data.description,
            humidity=weather_data.humidity,
            wind_speed=weather_data.wind_speed,
            timestamp=datetime.now()
        )
        db.add(weather_cache)
        logger.info(f"Cache entry created for city: {city}")
    db.commit()

@app.get("/{city}", response_model=WeatherResponse)
async def get_weather(city: str, db: Session = Depends(get_db)):
    logger.info(f"Received request for weather data in city: {city}")
    
    cached_weather = await get_cached_weather(db, city)
    if cached_weather:
        logger.info(f"Returning cached weather data for city: {city}")
        return cached_weather

    logger.info(f"No valid cache found for city: {city}, fetching from API")
    weather_data = await fetch_weather_from_api(city)
    await update_cache(db, city, weather_data)
    logger.info(f"Returning fresh weather data for city: {city}")
    return weather_data
