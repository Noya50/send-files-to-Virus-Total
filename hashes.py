import hashlib

def get_file_hash(path: str) -> str:
    hash = hashlib.sha256()
    
    with open(path, 'rb') as f:
        content = f.read()
        hash.update(content)
        result = hash.hexdigest()
        return result
        
h = get_file_hash(r"C:\Users\lapto\Downloads\ASPNET\Microsoft.VisualStudio.MinShell.Auto,version=17.11.35208.52\payload.vsix")
print(h)