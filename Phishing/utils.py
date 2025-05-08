import requests
import validators
def extract_destination_url(masked_url):
    print(masked_url)
    try:
        response = requests.get(masked_url)
        destination_url = response.url
        return destination_url

    except requests.exceptions.ConnectionError:
        return masked_url

    except (ValueError, TypeError):
        return ''


def unmask(mask_url):
    if not mask_url or not isinstance(mask_url, str):
        return 'not a valid url'

    # Automatically prepend https:// if missing
    if not mask_url.startswith(('http://', 'https://')):
        mask_url = 'https://' + mask_url

    # Validate URL structure
    if not validators.url(mask_url):
        return 'not a valid url'

    # Try to follow redirection
    try:
        response = requests.head(mask_url, allow_redirects=True, timeout=5)
        return response.url
    except requests.RequestException:
        return mask_url  # If not reachable, return original URL

    else:
        pass




