import pathlib

# Example 1: Path construction
uri = "index.html"
file_path = pathlib.Path(__file__).parent / uri
print('\nfile_path: %s\n' % file_path)

#---------------------------------

# Example 2: Testing file existence
uris = ["index.html", "", "/", "inde", "/data/", "/data", "/data/example.tet", "/data/example.txt", "/data/example.png", "/data/Example.png"]


for uri in uris:
    if uri.startswith('/'):
        uri = uri[1:]
    file_path = pathlib.Path(__file__).parent / uri
    print(f'\nfile_path: {file_path}')
    print(f'file_path for {uri} existed?: {file_path.exists()}\n')


# Example 2: Testing file or folder
uris = ["/index.html", "", "/", "inde", "/data/", "/data","data","data/", "/data/example.tet", "/data/example.txt", "/data/example.png", "/data/Example.png"]


for uri in uris:
    if uri.startswith('/'):
        uri = uri[1:]
    file_path = pathlib.Path(__file__).parent / uri
    if not file_path.exists():
        print(f'\n{uri} does not exist')
    else:
        if file_path.is_file():
            print(f'\n{uri} is a file')
        elif file_path.is_dir():
            print(f'\n{uri} is a folder')