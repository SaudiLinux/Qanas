# Qanas Wordlists Package
# Author: Saudi Linux (SaudiLinux1@gmail.com)

"""
Qanas Wordlists

This package contains wordlists used by Qanas for various scanning and enumeration tasks.
Wordlists are organized by category and can be used for tasks such as:
- Subdomain enumeration
- Directory brute forcing
- Password attacks
- Common vulnerability checks

Wordlists can be added or updated as needed.
"""

import os
import json

# Base directory for wordlists
WORDLISTS_DIR = os.path.dirname(os.path.abspath(__file__))

# Wordlist categories
CATEGORIES = {
    'subdomains': 'Subdomain enumeration wordlists',
    'directories': 'Web directory and file wordlists',
    'passwords': 'Common password wordlists',
    'usernames': 'Common username wordlists',
    'vulnerabilities': 'Vulnerability check wordlists',
    'custom': 'User-defined custom wordlists'
}

# Default wordlists by category
DEFAULT_WORDLISTS = {
    'subdomains': 'common_subdomains.txt',
    'directories': 'common_directories.txt',
    'passwords': 'common_passwords.txt',
    'usernames': 'common_usernames.txt',
    'vulnerabilities': 'common_vulns.txt'
}

def get_wordlist_path(category, wordlist_name=None):
    """
    Get the full path to a wordlist file
    
    Args:
        category (str): The category of the wordlist
        wordlist_name (str, optional): The name of the wordlist file. If None, uses the default for the category.
        
    Returns:
        str: The full path to the wordlist file
    """
    if category not in CATEGORIES:
        raise ValueError(f"Unknown wordlist category: {category}")
    
    # If no specific wordlist is requested, use the default for the category
    if wordlist_name is None:
        if category in DEFAULT_WORDLISTS:
            wordlist_name = DEFAULT_WORDLISTS[category]
        else:
            # For custom category with no default, return the directory
            return os.path.join(WORDLISTS_DIR, category)
    
    return os.path.join(WORDLISTS_DIR, category, wordlist_name)

def list_wordlists(category=None):
    """
    List available wordlists
    
    Args:
        category (str, optional): The category to list wordlists for. If None, lists all wordlists.
        
    Returns:
        dict: A dictionary of available wordlists by category
    """
    result = {}
    
    if category:
        if category not in CATEGORIES:
            raise ValueError(f"Unknown wordlist category: {category}")
        categories = [category]
    else:
        categories = CATEGORIES.keys()
    
    for cat in categories:
        cat_dir = os.path.join(WORDLISTS_DIR, cat)
        if os.path.exists(cat_dir) and os.path.isdir(cat_dir):
            result[cat] = []
            for filename in os.listdir(cat_dir):
                if os.path.isfile(os.path.join(cat_dir, filename)) and not filename.startswith('.'):
                    file_path = os.path.join(cat_dir, filename)
                    file_size = os.path.getsize(file_path)
                    line_count = 0
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            line_count = sum(1 for _ in f)
                    except Exception:
                        pass
                    
                    result[cat].append({
                        'name': filename,
                        'path': file_path,
                        'size': file_size,
                        'entries': line_count,
                        'default': (filename == DEFAULT_WORDLISTS.get(cat, ''))
                    })
    
    return result

def create_wordlist_structure():
    """
    Create the initial wordlist directory structure
    """
    for category in CATEGORIES:
        category_dir = os.path.join(WORDLISTS_DIR, category)
        if not os.path.exists(category_dir):
            os.makedirs(category_dir, exist_ok=True)

def add_wordlist(category, wordlist_name, entries):
    """
    Add a new wordlist to a category
    
    Args:
        category (str): The category for the wordlist
        wordlist_name (str): The name of the wordlist file
        entries (list): A list of entries to add to the wordlist
        
    Returns:
        str: The path to the created wordlist
    """
    if category not in CATEGORIES:
        raise ValueError(f"Unknown wordlist category: {category}")
    
    category_dir = os.path.join(WORDLISTS_DIR, category)
    if not os.path.exists(category_dir):
        os.makedirs(category_dir, exist_ok=True)
    
    wordlist_path = os.path.join(category_dir, wordlist_name)
    
    with open(wordlist_path, 'w', encoding='utf-8') as f:
        for entry in entries:
            f.write(f"{entry}\n")
    
    return wordlist_path

def load_wordlist(category, wordlist_name=None):
    """
    Load a wordlist into memory
    
    Args:
        category (str): The category of the wordlist
        wordlist_name (str, optional): The name of the wordlist file. If None, uses the default for the category.
        
    Returns:
        list: The entries in the wordlist
    """
    wordlist_path = get_wordlist_path(category, wordlist_name)
    
    if not os.path.exists(wordlist_path):
        raise FileNotFoundError(f"Wordlist not found: {wordlist_path}")
    
    with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
        return [line.strip() for line in f if line.strip()]

# Create the wordlist structure when the module is imported
create_wordlist_structure()