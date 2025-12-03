import base64
import os
import json
import time
import getpass
from typing import List, Optional
from fastapi import FastAPI, Header, HTTPException, Request, Body
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
import uvicorn
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from pydantic import BaseModel

import pyotp

app = FastAPI()

class OTPResponse(BaseModel):
    issuer: str
    name: str
    otp: str
    period: int

class OTPCreateRequest(BaseModel):
    issuer: str
    name: str
    secret: str

def get_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def load_encrypted_data(password: str):
    """encrypted.binを読み込んで復号化し、JSONオブジェクトとソルトを返すヘルパー関数"""
    if not os.path.exists("encrypted.bin"):
        raise HTTPException(status_code=404, detail="encrypted.bin not found.")

    with open("encrypted.bin", "rb") as file:
        file_content = file.read()
    
    # ファイル構造: [Salt (16 bytes)] + [Encrypted Data]
    salt = file_content[:16]
    encrypted_data = file_content[16:]
    
    # キーの生成と復号化
    try:
        key = get_key(password, salt)
        f = Fernet(key)
        decrypted_data = f.decrypt(encrypted_data)
        return json.loads(decrypted_data.decode('utf-8')), salt
    except InvalidToken:
        raise HTTPException(status_code=401, detail="Invalid password")
    except Exception as e:
        print(f"Error loading data: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")

def save_encrypted_data(data: list, password: str, salt: bytes):
    """データを暗号化して保存するヘルパー関数"""
    key = get_key(password, salt)
    f = Fernet(key)
    json_data = json.dumps(data).encode('utf-8')
    encrypted_data = f.encrypt(json_data)
    
    with open("encrypted.bin", "wb") as file:
        file.write(salt + encrypted_data)

@app.get("/api/otp", response_model=List[OTPResponse])
async def get_otps(x_password: str = Header(..., alias="X-Password")):
    """
    ヘッダーのパスワードを使用してencrypted.binを復号化し、
    現在のOTP情報を返します。
    """
    accounts, _ = load_encrypted_data(x_password)
    
    response_data = []
    for acc in accounts:
        secret = acc.get("secret")
        if not secret:
            continue
            
        try:
            totp = pyotp.TOTP(secret)
            current_otp = totp.now()
            
            response_data.append(OTPResponse(
                issuer=acc.get("issuer", "Unknown"),
                name=acc.get("name", "Unknown"),
                otp=current_otp,
                period=totp.interval
            ))
        except Exception:
            continue
            
    return response_data

@app.post("/api/otp")
async def add_otp(otp_data: OTPCreateRequest, x_password: str = Header(..., alias="X-Password")):
    """
    新しいOTP情報を追加します。
    """
    # 既存データの読み込み
    accounts, salt = load_encrypted_data(x_password)
    
    # Secretの簡単な検証（pyotpでインスタンス化できるか）
    try:
        pyotp.TOTP(otp_data.secret)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid Secret Key")
    
    # 新しいデータ形式
    new_entry = {
        "issuer": otp_data.issuer,
        "name": otp_data.name,
        "secret": otp_data.secret
    }
    
    accounts.append(new_entry)
    
    # 保存
    save_encrypted_data(accounts, x_password, salt)
    
    return {"message": "OTP added successfully"}

# 静的ファイルのmount
if not os.path.exists("static"):
    os.makedirs("static")

app.mount("/", StaticFiles(directory="static", html=True), name="static")

def initialize_file_if_needed():
    """起動時にファイルが存在しない場合、パスワードを設定して作成する"""
    if not os.path.exists("encrypted.bin"):
        print("\n=== 初期設定 ===")
        print("encrypted.bin が見つかりません。")
        print("新しいストレージを作成します。")
        
        while True:
            try:
                password = getpass.getpass("マスターパスワードを設定してください: ")
                if not password:
                    print("パスワードは空にできません。")
                    continue
                    
                confirm = getpass.getpass("確認のためもう一度入力してください: ")
                
                if password == confirm:
                    break
                else:
                    print("パスワードが一致しません。もう一度試してください。")
            except KeyboardInterrupt:
                print("\nキャンセルされました。終了します。")
                exit(1)
        
        # 初期データの作成（空リスト）
        salt = os.urandom(16)
        save_encrypted_data([], password, salt)
        print("設定が完了しました。サーバーを起動します。\n")

if __name__ == "__main__":
    initialize_file_if_needed()
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="warning")
