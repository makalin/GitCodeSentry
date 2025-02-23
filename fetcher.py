import requests
import base64

class GitHubFetcher:
    def __init__(self, url):
        self.url = url
        self.api_base = "https://api.github.com/repos"

    def fetch_files(self):
        # Convert URL to API endpoint (e.g., https://github.com/org/repo -> org/repo)
        parts = self.url.split('/')
        repo_path = f"{parts[-2]}/{parts[-1]}"
        api_url = f"{self.api_base}/{repo_path}/contents"
        
        files = {}
        response = requests.get(api_url)
        if response.status_code != 200:
            raise Exception(f"Failed to fetch repo: {response.status_code}")
        
        for item in response.json():
            if item['type'] == 'file':
                file_url = item['download_url']
                content = requests.get(file_url).text
                files[item['path']] = content
        return files