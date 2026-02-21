#!/usr/bin/env python3
import os
import json
import hmac
import hashlib
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


class SecureChannel:
    """安全通信通道"""
    
    def __init__(self, encryption_key, auth_token):
        """
        初始化安全通道
        
        Args:
            encryption_key: 加密密钥（至少32字节）
            auth_token: 身份验证令牌
        """
        if not encryption_key or len(encryption_key) < 32:
            raise ValueError("加密密钥长度必须至少32字节")
        
        if not auth_token:
            raise ValueError("身份验证令牌不能为空")
        
        # 使用PBKDF2派生32字节密钥
        self.encryption_key = self._derive_key(encryption_key.encode('utf-8'))
        self.auth_token = auth_token.encode('utf-8')
        self.aesgcm = AESGCM(self.encryption_key)
    
    def _derive_key(self, password, salt=b'node_monitor_salt', iterations=100000):
        """使用PBKDF2派生密钥"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        return kdf.derive(password)
    
    def encrypt_message(self, data):
        """
        加密并签名消息
        
        Args:
            data: 要加密的数据（dict）
            
        Returns:
            加密后的消息（JSON字符串）
        """
        try:
            # 1. 将数据转换为JSON字符串
            json_data = json.dumps(data, ensure_ascii=False)
            plaintext = json_data.encode('utf-8')
            
            # 2. 生成随机nonce（12字节）
            nonce = os.urandom(12)
            
            # 3. 使用AES-GCM加密
            ciphertext = self.aesgcm.encrypt(nonce, plaintext, None)
            
            # 4. 计算HMAC签名
            signature = self._sign_data(nonce + ciphertext)
            
            # 5. 组装加密消息
            encrypted_message = {
                'nonce': b64encode(nonce).decode('utf-8'),
                'ciphertext': b64encode(ciphertext).decode('utf-8'),
                'signature': signature,
                'version': '1.0'
            }
            
            return json.dumps(encrypted_message)
            
        except Exception as e:
            raise Exception(f"加密消息失败: {e}")
    
    def decrypt_message(self, encrypted_data):
        """
        验证并解密消息
        
        Args:
            encrypted_data: 加密的消息（JSON字符串）
            
        Returns:
            解密后的数据（dict）
        """
        try:
            # 1. 解析加密消息
            encrypted_message = json.loads(encrypted_data)
            
            nonce = b64decode(encrypted_message['nonce'])
            ciphertext = b64decode(encrypted_message['ciphertext'])
            signature = encrypted_message['signature']
            
            # 2. 验证HMAC签名
            if not self._verify_signature(nonce + ciphertext, signature):
                raise ValueError("签名验证失败，消息可能被篡改")
            
            # 3. 使用AES-GCM解密
            plaintext = self.aesgcm.decrypt(nonce, ciphertext, None)
            
            # 4. 解析JSON数据
            json_data = plaintext.decode('utf-8')
            data = json.loads(json_data)
            
            return data
            
        except json.JSONDecodeError as e:
            raise Exception(f"JSON解析失败: {e}")
        except Exception as e:
            raise Exception(f"解密消息失败: {e}")
    
    def _sign_data(self, data):
        """使用HMAC-SHA256签名数据"""
        h = hmac.new(self.auth_token, data, hashlib.sha256)
        return h.hexdigest()
    
    def _verify_signature(self, data, signature):
        """验证HMAC签名"""
        expected_signature = self._sign_data(data)
        return hmac.compare_digest(expected_signature, signature)
    
    def verify_auth_token(self, provided_token):
        """验证身份令牌"""
        if not provided_token:
            return False
        return hmac.compare_digest(
            self.auth_token,
            provided_token.encode('utf-8')
        )


def create_secure_channel_from_env():
    """从环境变量创建安全通道"""
    encryption_key = os.getenv('NODE_ENCRYPTION_KEY')
    auth_token = os.getenv('NODE_AUTH_TOKEN')
    
    if not encryption_key:
        raise ValueError("环境变量 NODE_ENCRYPTION_KEY 未设置")
    if not auth_token:
        raise ValueError("环境变量 NODE_AUTH_TOKEN 未设置")
    
    return SecureChannel(encryption_key, auth_token)

