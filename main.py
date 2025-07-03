from datetime import timedelta
from fastapi import FastAPI, Request, Depends, status, Form, Response, Path
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.encoders import jsonable_encoder
from starlette.status import HTTP_400_BAD_REQUEST
from db import SessionLocal, engine, DBContext
import models, crud, schemas
from sqlalchemy.orm import Session
from fastapi_login import LoginManager
from dotenv import load_dotenv
import os
from passlib.context import CryptContext
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm

load_dotenv()
SECRET_KEY = os.getenv('SECRET_KEY')
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Custom exception for unauthenticated access
class NotAuthenticatedException(Exception):
    pass

# Redirect handler for our custom exception
def not_authenticated_exception_handler(request: Request, exc: NotAuthenticatedException):
    return RedirectResponse("/login")

# Initialize the LoginManager with our custom exception
manager = LoginManager(
    SECRET_KEY,
    token_url="/login",
    use_cookie=True,
    not_authenticated_exception=NotAuthenticatedException
)
manager.cookie_name = "auth"

app = FastAPI()

# Register the exception handler
app.add_exception_handler(NotAuthenticatedException, not_authenticated_exception_handler)

templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_db():
    with DBContext() as db:
        yield db

def get_hashed_password(plain_password: str) -> str:
    return pwd_ctx.hash(plain_password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_ctx.verify(plain_password, hashed_password)

@manager.user_loader()
def get_user(username: str, db: Session = None):
    if db is None:
        with DBContext() as db:
            return crud.get_user_by_username(db=db, username=username)
    return crud.get_user_by_username(db=db, username=username)

def authenticate_user(
    username: str,
    password: str,
    db: Session = Depends(get_db)
):
    user = crud.get_user_by_username(db=db, username=username)
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user

@app.get("/")
def root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "title": "Home"})

@app.get("/tasks")
def get_tasks(
    request: Request,
    db: Session = Depends(get_db),
    user: schemas.User = Depends(manager)
):
    tasks = crud.get_tasks_by_user_id(db=db, id=user.id)
    return templates.TemplateResponse(
        "tasks.html",
        {"request": request, "title": "Tasks", "user": user, "tasks": tasks}
    )

@app.post("/tasks")
def add_task(
    request: Request,
    text: str = Form(...),
    db: Session = Depends(get_db),
    user: schemas.User = Depends(manager)
):
    added = crud.add_task(db=db, task=schemas.TaskCreate(text=text), id=user.id)
    if not added:
        return templates.TemplateResponse(
            "tasks.html",
            {
                "request": request,
                "title": "Tasks",
                "user": user,
                "tasks": crud.get_tasks_by_user_id(db=db, id=user.id),
                "invalid": True
            },
            status_code=status.HTTP_400_BAD_REQUEST
        )
    return RedirectResponse("/tasks", status_code=status.HTTP_302_FOUND)

@app.get("/tasks/delete/{id}", response_class=RedirectResponse)
def delete_task(
    id: str = Path(...),
    db: Session = Depends(get_db),
    user: schemas.User = Depends(manager)
):
    crud.delete_task(db=db, id=id)
    return RedirectResponse("/tasks")

@app.get("/login")
def get_login(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "title": "Login"})

@app.post("/login")
def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "title": "Login", "invalid": True},
            status_code=status.HTTP_401_UNAUTHORIZED
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = manager.create_access_token(
        data={"sub": user.username},
        expires=access_token_expires
    )
    resp = RedirectResponse("/tasks", status_code=status.HTTP_302_FOUND)
    manager.set_cookie(resp, access_token)
    return resp

@app.get("/register")
def get_register(request: Request):
    return templates.TemplateResponse("register.html", {"request": request, "title": "Register"})

@app.post("/register")
def register(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    name: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    invalid = False
    if crud.get_user_by_username(db=db, username=username):
        invalid = True
    if crud.get_user_by_email(db=db, email=email):
        invalid = True

    if invalid:
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "title": "Register", "invalid": True},
            status_code=HTTP_400_BAD_REQUEST
        )

    hashed_password = get_hashed_password(password)
    crud.create_user(
        db=db,
        user=schemas.UserCreate(
            username=username,
            email=email,
            name=name,
            hashed_password=hashed_password
        )
    )
    return RedirectResponse("/login", status_code=status.HTTP_302_FOUND)

@app.get("/logout")
def logout(response: Response):
    resp = RedirectResponse("/")
    manager.set_cookie(resp, None)
    return resp
