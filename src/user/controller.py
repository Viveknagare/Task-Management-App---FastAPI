from src.user.dtos import UserSchema, LoginSchema
from sqlalchemy.orm import Session
from src.user.models import UserModel
from fastapi import HTTPException, status, Request
from pwdlib import PasswordHash
from src.utils.settings import settings
from datetime import datetime, timedelta, timezone
from jwt.exceptions import InvalidTokenError
import jwt



password_hash = PasswordHash.recommended()

def get_password_hash(password):
    return password_hash.hash(password)

def verify_password(plain_password, hashed_password):
    return password_hash.verify(plain_password, hashed_password)


def register(body : UserSchema, db : Session):
    is_user = db.query(UserModel).filter(UserModel.username == body.username).first()
    
    if is_user:
        raise HTTPException(400, detail="Username already exists...")
    
    is_user = db.query(UserModel).filter(UserModel.email == body.email).first()
    
    if is_user:
        raise HTTPException(400, detail="Email Already exists")
    
    hash_password = get_password_hash(body.password)
    
    new_user = UserModel(
        name = body.name,
        username = body.username,
        hash_password = hash_password,
        email = body.email
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return new_user

def login_user(body : LoginSchema, db : Session):
    user = db.query(UserModel).filter(body.username == UserModel.username).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail = "You entered wrong username !") # we can also direcly write 401 instead of status_code = status.[status] 
    
    if not verify_password(body.password, user.hash_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail = "You entered wrong password !")
    
    print(datetime.now())
    exp_time = datetime.now() + timedelta(minutes=settings.EXP_TIME)
    print(exp_time)
    token = jwt.encode({"_id" : user.id, "exp" : exp_time.timestamp()}, settings.SECRET_KEY, settings.ALGORITHM) #after the exp time token will get expired and user will have to login again and generate new token
        
    return {"token" : token}


# token -> send

def is_authenticated(request : Request, db : Session):
    try:
        token = request.headers.get("authorization") # try to use .get for dictionary as it returns None, if you use [""] method then it will return key not found error and code will break
        if not token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="you are unauthorized")

        token = token.split(" ")[-1]
        
        
        data = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=settings.ALGORITHM
        )     
        user_id = data["_id"]
        
        #This is manual way of checking but the jwt.encode method automatically internally checks whether the token has expired or not, if it is expired then it raises Invalid Token Error
        # print(data)
        # current_time = datetime.now().timestamp()
        # exp_time = data["exp"]
        # print(exp_time - current_time)
        # if current_time > exp_time:
        #     raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="you are unauthorized")
        
        user = db.query(UserModel).filter(UserModel.id == user_id).first()
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="you are unauthorized")
        
        return user
    except InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="you are unauthorized")

