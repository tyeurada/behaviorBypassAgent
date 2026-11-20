import requests
import sys

BASE_URL = "http://127.0.0.1:5001"

def test_api():
    try:
        # 1. Test Root
        print(f"Checking {BASE_URL}...")
        resp = requests.get(BASE_URL)
        if resp.status_code == 200 and "<!doctype html>" in resp.text.lower():
            print("[PASS] Root URL serves HTML")
        else:
            print(f"[FAIL] Root URL returned {resp.status_code}")
            return False

        # 2. Test Sessions List
        print(f"Checking {BASE_URL}/api/sessions...")
        resp = requests.get(f"{BASE_URL}/api/sessions")
        if resp.status_code == 200:
            sessions = resp.json()
            print(f"[PASS] Found {len(sessions)} sessions")
            
            if len(sessions) > 0:
                first_session = sessions[0]['id']
                print(f"Testing details for session: {first_session}")
                
                # 3. Test Session Details
                resp = requests.get(f"{BASE_URL}/api/sessions/{first_session}")
                if resp.status_code == 200:
                    details = resp.json()
                    print(f"[PASS] Session details retrieved. Iterations: {len(details['iterations'])}")
                    
                    if len(details['iterations']) > 0:
                        first_iter = details['iterations'][0]
                        print(f"First iteration has prompt: {first_iter['has_prompt']}")
                        print(f"First iteration has response: {first_iter['has_response']}")
                else:
                    print(f"[FAIL] Session details returned {resp.status_code}")
                    return False
        else:
            print(f"[FAIL] Sessions list returned {resp.status_code}")
            return False

        return True
    except Exception as e:
        print(f"[ERROR] Connection failed: {e}")
        return False

if __name__ == "__main__":
    if test_api():
        print("\nVerification Successful!")
        sys.exit(0)
    else:
        print("\nVerification Failed!")
        sys.exit(1)
