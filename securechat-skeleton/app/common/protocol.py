from pydantic import BaseModel
from typing import Optional

class Hello(BaseModel):
    client_id: str
    nonce: str

class ServerHello(BaseModel):
    server_id: str
    nonce: str
    server_cert: str  
    signature: str    

class Register(BaseModel):
    username: str
    password: str
    public_key: str  

class Login(BaseModel):
    username: str
    password: str
    nonce: str

class DHClient(BaseModel):
    g: int
    p: int
    A: int  
    signature: Optional[str] = None  

class DHServer(BaseModel):
    B: int  
    signature: Optional[str] = None  

class Msg(BaseModel):
    ciphertext: str
    iv: Optional[str] = None
    signature: Optional[str] = None
    timestamp: Optional[int] = None

class Receipt(BaseModel):
    msg_id: str
    status: str      
    signature: Optional[str] = None
