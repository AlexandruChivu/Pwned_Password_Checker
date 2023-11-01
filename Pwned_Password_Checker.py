import hashlib
import sys
import requests

def request_api_data(query_char):
    """
    Makes a GET request to the Pwned Passwords API to retrieve password hashes
    that start with the given query character.
    
    Args:
        query_char (str): The first five characters of the SHA-1 hashed password.

    Returns:
        requests.Response: The response object from the API request.
    """
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the API and try again')
    return res

def get_password_leaks_count(hashes, hash_to_check):
    """
    Parses the response from the Pwned Passwords API and returns
    the count of occurrences for a given password hash.
    
    Args:
        hashes (str): The response text from the API containing password hashes and their counts.
        hash_to_check (str): The SHA-1 hashed password to check for leaks.

    Returns:
        int: The count of occurrences for the given password hash.
    """
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return int(count)
    return 0

def pwned_api_check(password):
    """
    Checks if a password has been pwned (compromised) by
    sending a request to the Pwned Passwords API.
    
    Args:
        password (str): The password to be checked.

    Returns:
        int: The count of occurrences for the given password hash or 0 if not found.
    """
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)

def main(args):
    """
    Main function for checking the security of passwords from command line arguments.
    
    Args:
        args (list): List of password strings to be checked.

    Returns:
        str: A message indicating the completion of the operation.
    """
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times... you should probably change your password')
        else:
            print(f'{password} was not found. Carry on!')
    return "done"

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
