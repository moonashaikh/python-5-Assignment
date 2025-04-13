#  Develop a streamlit based secure data storage and retrieval system

import streamlit as st # type: ignore
import hashlib 
import json
import os
import time
from cryptography.fernet import Fernet # type: ignore
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

#  *** Data information of user ****

DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"
LOCKOUT_DURATION = 60

# **** section login detail ***

if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None
    
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
    
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0    

#  if data is load

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE ,"r") as f:
            return json.load(f)
        return{}

def save_data(data):
    with open(DATA_FILE ,"w") as f:
        json.dump(data,f)        


def generate_key(passkey):   
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)    
    return urlsafe_b64encode(key)

def hash_password(password):
    return hashlib.pbkdf2_hmac('sha256'.password.encode(),SALT,100000).hex()

# cryptography.fernet used
def encrypt_text(text,key):
    cipher = Fernet(generate_key(key)) 
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypt_text,key):
    try:
       cipher = Fernet(generate_key(key))
       return cipher.decrypt(encrypt_text.encode()).decode()
    except:
        return None
    
stored_data = load_data()
    
    # **Navigation bar ***
st.title("🔒 Secure Data Encryption System")
menu = ["Home" , "Register" ,"Login" , "store Date" , "Retrieve Date"]
choice = st.sidebar.selectbox("Navigation", menu)
    
if choice == "Home":
    st.subheader("welcome to 🔒 Data Encryption System Using Streamlit")
    st.markdown("Develop a streamlit-based storage and retrieval system  system  where: users store data,with a unique passkey. user decrypt data by providing the correct passkey,Multiple failed attempts result in a forced reauthorization(login page).The system operates entirely in memory without external database.")
        
        #  user registration
        
elif choice == 'Register':
      st.subheader(" Register New User")
      username = st.text_input("Choose Username")
      password = st.text_input("Choose Password", type="Password")
            
      if st.button("Register"):
        if  username and password:
            if username in stored_data:
                st.warning("⚠️user already exits!")
            else:
                stored_data[username]={
                    "password" : hash_password(password),
                    "data"  : []
                    }   
                save_data(stored_data)
                st.success("✅User Register Successfully!") 
        else:
                st.error("Both field are required")
elif choice == 'Login': 
            st.subheader("🗝️ User Login")  
        
            if time.time() < st.session_state.lockout_time:
               remaining = int(st.session_state.lockout_time -time.time()) 
               st.error(f"⏱️ too many failed attempt , please wait{remaining} seconds")  
               st.stop()
            
            username = st.text_input("Username")  
            password = st.text_input("Password", type="Password")  
if st.button("Login"):
             if username in stored_data and stored_data[username]["password"]== hash_password(password):
                 
                                  
                st.session_state.authenticated_user = username
                st.session_state.failed_attempts = 0
                st.success(f" ✅ welcome{username}!")
             else:
                 st.session_state.failed_attempts +=1
                 remaining=3 -st.session_state.failed_attempts
                 st.error(f"❌ Invalid attempt left{remaining}!" )
                 
if st.session_state.failed_attempts >= 3:
            st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
            st.error(" ⛔too many failed attempt , locked for 60 seconds" )
            st.stop()
            
            # ***data store section ****
elif choice == "store Data":
        if not st.session_state.authenticated_user:
            st.warning("🔒 Please Login First")
        else:
            st.subheader("⚡Store Encrypted Data")
            data= st.text_area("Enter Data to Encrypt")
            passkey = st.text_input("Encryption Key(passphrase)" ,type="password")
        if  st.button("Encrypt and save"):
            if data and passkey:
                    encrypted = encrypt_text(data, passkey)
                    stored_data[st.session_state.authenticated_user["data"].append(encrypted)]
                    save_data(stored_data)
                    st.success("✅ Data Encrypted and save successfully")
            else:
                    st.error("All field are required to fill")
        #  Data retrieve data section
        elif choice == "Retrieve Data":
            if not st.session_state.authenticated_user:
                
                st.warning("🔒Please Login First")
            else:
                st.subheader("🔍Retrieve Data")
                user_data = stored_data.get(st.session_state.authenticated_user , {}).get("data" , [])
            
            if not user_data:
                st.info("No User Data Found") 
            else:
                st.write("Encrypted Data Entries")
                for i, item in enumerate(user_data):
                    st.code(item, language = "text")
                    
                encrypted_input = st.text_area("Enter Encrypted text")
                passkey = st.text_input("Enter Passkey T Decrypt" , type="password")
                
            if st.button("Decrypt"):
                result = decrypt_text(encrypted_input , passkey)
                if result:
                   st.success(f"✅Decrypted : {result}")
                else:
                  st.error("❌ Incorrect Passkey or corrupted data")