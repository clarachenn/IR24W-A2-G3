# Juan, Athena, Clara, Laila
import re
import sys
from urllib.parse import urlparse
from bs4 import BeautifulSoup


visited_urls = set()
unique_urls = set()

def scraper(url, resp):
    links = extract_next_links(url, resp)
    return [link for link in links if is_valid(link)]

def extract_next_links(url, resp):
    # Implementation required.
    # url: the URL that was used to get the page
    # resp.url: the actual url of the page
    # resp.status: the status code returned by the server. 200 is OK, you got the page. Other numbers mean that there was some kind of problem.
    # resp.error: when status is not 200, you can check the error here, if needed.
    # resp.raw_response: this is where the page actually is. More specifically, the raw_response has two parts:
    #         resp.raw_response.url: the url, again
    #         resp.raw_response.content: the content of the page!
    # Return a list with the hyperlinks (as strings) scrapped from resp.raw_response.content

    links = []
    new_unique_urls = set()
    if is_valid(url) and resp.status == 200:
        soup = BeautifulSoup(resp.raw_response.content, "html.parser")
        tokenize_text(soup.get_text())
        a_tags = soup.find_all("a", href=True)
        for a_tag in a_tags:
            link = a_tag.get('href')
            if is_valid(link) and link not in visited_urls:
                links.append(link)
                visited_urls.add(link)
                # find the index of the fragment
                end_index = link.find("#")
                link_without_fragment = link[0:end_index]
                if end_index < 0: # If no fragment
                    if link not in unique_urls:
                        new_unique_urls.add(link)
                    unique_urls.add(link)
                else: # If fragment
                    if link not in unique_urls:
                        new_unique_urls.add(link)
                    unique_urls.add(link_without_fragment)
    return links



def is_valid(url):
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    try:
        parsed = urlparse(url)
        if parsed.scheme not in set(["http", "https"]):
            return False
        if ((".ics.uci.edu/" not in url) and (".cs.uci.edu/" not in url) and (".informatics.uci.edu/" not in url) and (".stat.uci.edu/" not in url)):
            return False
        return not re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1|java|py|db"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower())

    except TypeError:
        print ("TypeError for ", parsed)
        raise


def tokenize_text(text: str):
    lowercase_content = text.lower()  # convert all words to lowercase
    tokens = re.split(r'[^a-zA-Z0-9]', lowercase_content.strip())  # tokens can only be alphanumeric
    token_list = list(filter(None, tokens))

    try:
        token_frequency = {}
        for token in token_list:
            if token in token_frequency:  # if the key exists, increment its frequency
                token_frequency[token] += 1
            else:  # if the key doesn't exist, add it to the dictionary and update its frequency
                token_frequency[token] = 1
        print(token_frequency)
        sys.exit()
    except Exception as e:
        print(e)
    
