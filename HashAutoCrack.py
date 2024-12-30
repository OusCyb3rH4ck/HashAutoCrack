#!/usr/bin/env python3

from colorama import Fore, Style
import sys, os, argparse, time, requests, signal, hashlib, hashid, bcrypt, binascii

def def_handler(sig, frame):
    print(f"{Fore.LIGHTRED_EX+Style.DIM}\n\n[!] Exiting...\n")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

def ntlm_pw_crack(hash):
    url = f"https://ntlm.pw/{hash}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            print(f"{Fore.GREEN+Style.BRIGHT}\n[+] Hash cracked (from ntlm.pw):{Style.RESET_ALL} {response.text}")
            return response.text
        elif response.status_code == 204:
            print(f"{Fore.RED}\n[!] Hash not found in ntlm.pw\n{Style.RESET_ALL}")
            sys.exit(1)
        else:
            print(f"\nError: Unexpected status code {response.status_code} for hash '{hash}\n'")
            sys.exit(1)
    except Exception as e:
        print(f"[!] Error contacting ntlm.pw: {e}")
        sys.exit(1)

def crack_hash(hash, wordlist, type, salt=None, iterations=100000):
    print(f"{Fore.CYAN+Style.BRIGHT}\n[+] Hash provided:{Style.RESET_ALL} {hash}")
    print(f"{Fore.CYAN+Style.BRIGHT}[+] Wordlist provided:{Style.RESET_ALL} {wordlist}\n{Style.RESET_ALL}")
    
    if type:
        print(f"{Fore.CYAN+Style.BRIGHT}[+] Hash type provided:{Style.RESET_ALL} {str.upper(type)}\n{Style.RESET_ALL}")
    else:
        identify_hash = hashid.HashID()
        detected_hashes = identify_hash.identifyHash(hash)
        
        if detected_hashes:
            print(f"{Fore.GREEN+Style.BRIGHT}[+] Detected hash types:{Style.RESET_ALL}")
            for h in detected_hashes:
                print(f"    {Fore.YELLOW}- {h.name} (Hashcat: {h.hashcat if h.hashcat else 'N/A'}, John: {h.john if h.john else 'N/A'})")
            available_hashes = sorted([h for h in hashlib.algorithms_available] + ["bcrypt", "pbkdf2", "ntlm"])
            print(f"{Fore.LIGHTBLUE_EX}\n[i] Available hash types: {Style.RESET_ALL}{', '.join(available_hashes)}\n")
        else:
            print(f"{Fore.RED}[!] Unable to determine the hash type.\n")
            sys.exit(1)

    if type and type.lower() == "ntlm":
        print(f"{Fore.CYAN+Style.BRIGHT}[+] Attempting to crack NTLM hash using ntlm.pw...{Style.RESET_ALL}")
        time.sleep(2)
        cracked_password = ntlm_pw_crack(hash)
        if cracked_password:
            return
    
    elif type and type.lower() == "bcrypt":
        print(f"{Fore.CYAN+Style.BRIGHT}[+] Attempting to crack bcrypt hash...\n{Style.RESET_ALL}")
        time.sleep(2)
        
        try:
            with open(wordlist, 'r', encoding='ISO-8859-1') as file:
                for word in file:
                    word = word.strip()
                    if bcrypt.checkpw(word.encode(), hash.encode()):
                        print(f"{Fore.GREEN+Style.BRIGHT}\n\n[+] Hash cracked:{Style.RESET_ALL} {word}\n")
                        return
                    else:
                        print(f"{Fore.RED+Style.DIM}[!] Trying: {word}{Style.RESET_ALL}", end="\r")
                print(f"{Fore.RED}\n[!] Hash not found in the wordlist.\n")
        except FileNotFoundError:
            print(f"{Fore.RED}[!] Wordlist file not found.\n")
        except Exception as e:
            print(f"{Fore.RED}[!] An error occurred: {e}\n")

    elif type and type.lower() == "pbkdf2":
        if not salt:
            print(f"{Fore.RED}[!] Salt not provided for PBKDF2 hash.\n")
            sys.exit(1)        
        
        print(f"{Fore.CYAN+Style.BRIGHT}[+] Salt provided:{Style.RESET_ALL} {salt}\n{Style.RESET_ALL}")
        print(f"{Fore.CYAN+Style.BRIGHT}[+] Iterations provided:{Style.RESET_ALL} {iterations}\n{Style.RESET_ALL}")
        print(f"{Fore.CYAN+Style.BRIGHT}[+] Attempting to crack PBKDF2 hash...\n{Style.RESET_ALL}")
        time.sleep(2)
        
        try:
            salt = binascii.unhexlify(salt)
        except Exception as e:
            print(f"{Fore.RED}[!] Error converting salt: {e}\n")
            sys.exit(1)
        
        try:
            with open(wordlist, 'r', encoding='ISO-8859-1') as file:
                for word in file:
                    word = word.strip()
                    hashed_word = hashlib.pbkdf2_hmac("sha256", word.encode(), salt, iterations)
                    if binascii.hexlify(hashed_word).decode() == hash:
                        print(f"{Fore.GREEN+Style.BRIGHT}\n\n[+] Hash cracked:{Style.RESET_ALL} {word}\n")
                        return
                    else:
                        print(f"{Fore.RED+Style.DIM}[!] Trying: {word}{Style.RESET_ALL}", end="\r")
                print(f"{Fore.RED}\n[!] Hash not found in the wordlist.\n")
        except FileNotFoundError:
            print(f"{Fore.RED}[!] Wordlist file not found.\n")
        except Exception as e:
            print(f"{Fore.RED}[!] An error occurred: {e}\n")

    elif type:        
        try:
            with open(wordlist, 'r', encoding='ISO-8859-1') as file:
                for word in file:
                    word = word.strip()
                    if type:
                        try:
                            hash_func = getattr(hashlib, type.lower())
                            hashed_word = hash_func(word.encode()).hexdigest()
                        except AttributeError:
                            print(f"{Fore.RED}[!] Invalid hash type provided.\n{Style.RESET_ALL}")
                            available_hashes = sorted([h for h in hashlib.algorithms_available] + ["bcrypt", "pbkdf2", "ntlm"])
                            print(f"{Fore.LIGHTBLUE_EX}\n[i] Available hash types: {Style.RESET_ALL}{', '.join(available_hashes)}\n")
                            sys.exit(1)
                    else:
                        hashed_word = hashlib.md5(word.encode()).hexdigest()
                    
                    if hashed_word == hash:
                        print(f"{Fore.GREEN+Style.BRIGHT}\n\n[+] Hash cracked:{Style.RESET_ALL} {word}\n")
                        return
                    else:
                        print(f"{Fore.RED+Style.DIM}[!] Trying: {word}{Style.RESET_ALL}", end="\r")
                print(f"{Fore.RED}\n[!] Hash not found in the wordlist.\n")
        except FileNotFoundError:
            print(f"{Fore.RED}[!] Wordlist file not found.\n")
        except Exception as e:
            print(f"{Fore.RED}[!] An error occurred: {e}\n")

def main():
    os.system("clear && figlet HashAutoCrack | lolcat")
    print(f"{Fore.GREEN+Style.BRIGHT}Made by OusCyb3rH4ck\n{Style.RESET_ALL}")
    
    parser = argparse.ArgumentParser(description="HashAutoCrack - An automated hash cracker tool", usage="HashAutoCrack.py -H <hash> -w <wordlist> -t <hash_type>")
    parser.add_argument("-H", "--hash", help="Hash to crack", required=True)
    parser.add_argument("-w", "--wordlist", help="Wordlist file", required=True)
    parser.add_argument("-t", "--type", help="Hash type", required=False)
    parser.add_argument("-s", "--salt", help="Salt for PBKDF2 (required for PBKDF2)", required=False)
    parser.add_argument("-i", "--iterations", help="Number of iterations for PBKDF2 (default: 100000)", type=int, default=100000, required=False)

    args = parser.parse_args()

    crack_hash(args.hash, args.wordlist, args.type, args.salt, args.iterations)

if __name__ == "__main__":
    main()
