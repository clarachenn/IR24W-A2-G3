# BY: Juan, Athena, Clara, Laila

import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup


token_frequency = {}  # get the frequency of all the words processed from accross all documents
max_file = 0  # largest number of words (for largest document)
max_page = ""  # the largest document
subdomain_dict = {}  # keep track of subdomains found in the ics.uci.edu domain
visited_urls = set()  # documents that have been seen and processed
frontier_urls = set()  # documents not processed yet
unique_urls = set()  # all the visited urls, without the fragment
stop_words = ["a", "about", "above", "after", "again", "against", "all", "am", "an", "and", "any", "are", "aren't", "as", "at", "be", "because", "been", "before", "being", "below", "between", "both", "but", "by", "can't", "cannot", "could", "couldn't", "did", "didn't", "do", "does", "doesn't", "doing", "don't", "down", "during", "each", "few", "for", "from", "further", "had", "hadn't", "has", "hasn't", "have", "haven't", "having", "he", "he'd", "he'll", "he's", "her", "here", "here's", "hers", "herself", "him", "himself", "his", "how", "how's", "i", "i'd", "i'll", "i'm", "i've", "if", "in", "into", "is", "isn't", "it", "it's", "its", "itself", "let's", "me", "more", "most", "mustn't", "my", "myself", "no", "nor", "not", "of", "off", "on", "once", "only", "or", "other", "ought", "our", "ours", "ourselves", "out", "over", "own", "same", "shan't", "she", "she'd", "she'll", "she's", "should", "shouldn't", "so", "some", "such", "than", "that", "that's", "the", "their", "theirs", "them", "themselves", "then", "there", "there's", "these", "they", "they'd", "they'll", "they're", "they've", "this", "those", "through", "to", "too", "under", "until", "up", "very", "was", "wasn't", "we", "we'd", "we'll", "we're", "we've", "were", "weren't", "what", "what's", "when", "when's", "where", "where's", "which", "while", "who", "who's", "whom", "why", "why's", "with", "won't", "would", "wouldn't", "you", "you'd", "you'll", "you're", "you've", "your", "yours", "yourself", "yourselves"]
fingerprint_set = set() # set of all the fingerprints of visited sites
checksum_set = set()
robots_checked = set()
max_redirects = 20


def write_result():
    sorted_token_frequency = sorted(token_frequency.items(), key=lambda x: x[1], reverse=True)
    top_50_words = sorted_token_frequency[:50]

    with open("crawler_results.txt", "w") as file:
        file.write("1. Unique Pages:\n")
        file.write(str(len(unique_urls)))
        file.write("\n")

        for url in unique_urls:
            file.write(f"{url}")
            file.write("\n")

        file.write("\n")
        file.write("\n")

        file.write("2. Longest Page:\n")
        file.write(max_page)
        file.write("\n")
        file.write(str(max_file))

        file.write("\n")
        file.write("\n")

        file.write("3. 50 Most Common Words:\n")
        for word, frequency in top_50_words:
            file.write(f"{word}: {frequency}")
            file.write("\n")
        file.write("\n")


        file.write("4. Subdomains Found:\n")
        file.write(str(len(subdomain_dict)) + "\n")

        # Iterate over each subdomain and its corresponding value, sorted alphabetically
        for subdomain, value in sorted(subdomain_dict.items()):
            file.write(f"{subdomain}: {value}\n")
        file.write("\n")

def scraper(url, resp):
    links = extract_next_links(url, resp)
    return [link for link in links if is_valid(link)]


def extract_next_links(url, resp, redirects_followed=0):
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

    # while resp.status >= 300 and resp.status < 400 and redirects_followed < max_redirects:
    #     if 'Location' in resp.raw_response.headers:
    #         url = resp.headers['Location']
    #         redirects_followed += 1
    #         return extract_next_links(url, resp, redirects_followed)

    # if redirects_followed == max_redirects:
    #     return []

    if is_valid(url) and resp.status == 200:
        # # check if this url is a subdomain
        # if url not in robots_checked and (url.endswith("ics.uci.edu") or url.endswith("cs.uci.edu") or url.endswith("informatics.uci.edu") or url.endswith("stat.uci.edu")):
        #     print("added robot link")
        #     robots_checked.add(url)
        #     url += "/robots.txt"
        #     return [url]

        # if "robots.txt" in url:
        #     soup = BeautifulSoup(resp.raw_response.content, "html.parser")
    
        #     # Find all lines containing the sitemap link
        #     sitemap_lines = [line for line in soup.get_text().split("\n") if "Sitemap:" in line]
            
        #     # Extract the sitemap URL from the first line
        #     if sitemap_lines:
        #         sitemap_url = sitemap_lines[0].split("Sitemap:")[1].strip()
        #         print(sitemap_url)
        #         return [sitemap_url]
        #     else:
        #         print("none")
        #         url = url.replace("/robots.txt", "")
        #         print("replaced url", url)
        #         return [url]

        # if url.endswith(".xml"):
        #     soup = BeautifulSoup(resp.raw_response.content, "html.parser")

        # finding the largest document
        soup = BeautifulSoup(resp.raw_response.content, "html.parser")
        visited_urls.add(url)

        # tokenizes each webpage
        page_dict, token_list = tokenize_text(soup.get_text())

        # dont crawl if page has too little or too much information
        if len(token_list) < 50 :
            return []

        # updates the largest file
        update_max(token_list, url)
        # updates the subdomain list
        update_subdomains(url)

        # get the fingerprint of each file
        fingerprint = simhash(page_dict)

        # get the sum of all tokens of each file 
        checksum_res = checksum(token_list)
        
        near_duplicate = False

        # check if the page is an exact duplicate 
        if checksum_res in checksum_set:
            return []
        else:
            checksum_set.add(checksum_res)

        # TODO: add to file to check
        if (fingerprint not in fingerprint_set):
            for i in range(16):
                # make a copy of the original fingerprint
                new_fingerprint = list(fingerprint)
                # flip 1 bit at a time to detect near similarity
                if new_fingerprint[i] == "1":
                    new_fingerprint[i] = "0"
                else:
                     new_fingerprint[i] = "1"
                if "".join(new_fingerprint) in fingerprint_set:
                    fingerprint_set.add(fingerprint)
                    near_duplicate = True
                    break

        if fingerprint in fingerprint_set:
            print("fingerprint exists: ", fingerprint)     
        if near_duplicate:
            print("near_duplicate true")     

        # check if fingerprint already exists to detect exact similarity or if there is near similarity
        if (fingerprint not in fingerprint_set) and not near_duplicate:        
            a_tags = soup.find_all("a", href=True)

            for a_tag in a_tags:
                link = a_tag.get('href')
                # make sure crawler doesn't fall into a trap
                if is_valid(link) and link not in frontier_urls and link not in visited_urls:
                    links.append(link)
                    frontier_urls.add(link)
                    # find the index of the fragment
                    end_index = link.find("#")
                    link_without_fragment = link[0:end_index]
                    if end_index < 0: # If no fragment
                        unique_urls.add(link)
                    else: # If fragment
                        unique_urls.add(link_without_fragment)
            
            # add fingerprint to the set
            fingerprint_set.add(fingerprint)      

    write_result()
    return links


def is_valid(url):
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    try:
        parsed = urlparse(url)
        if parsed.scheme not in set(["http", "https"]):
            return False
        if (("ics.uci.edu" not in url) and ("cs.uci.edu" not in url) and ("informatics.uci.edu" not in url) and ("stat.uci.edu" not in url)):
            return False
        return not re.match(
            r".*\.(ppsx|css|js|bmp|gif|jpe?g|ico"
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


def update_max(token_list, url):
    """
    Checks if the current document is larger than the existing largest document.
    """
    global max_file, max_page
    token_size = len(token_list)
    if token_size > max_file:
        max_file = token_size
        max_page = url


def update_subdomains(url):
    """
    If the current url is in the subdomain list, it increments its count by 1.
    """
    if "ics.uci.edu" in url:
        end_index = url.find("ics.uci.edu")
        subdomain = url[0:end_index + 11]
        if subdomain in subdomain_dict:  # if the subdomain exists, increment its number of unique pages
                subdomain_dict[subdomain] += 1
        else:  # if the subdomain doesn't exist, add it to the dictionary and update its number of unique pages
            subdomain_dict[subdomain] = 1


def tokenize_text(text: str) -> None:
    """
    Tokenize the text from the document. Find the top 50 words.
    """
    lowercase_content = text.lower()  # convert all words to lowercase
    tokens = re.split(r"[^\w\-'\.]", lowercase_content.strip()) # split by alphabets, nums, hyphens, apostrophes, and periods

    token_list = list(filter(None, tokens))
    page_dict = {}

    try:
        # iterate through all tokens to find frequencies; find top 50 words
        for token in token_list:
            # remove the last period if the token ends with one
            if token.endswith('.') and len(token) > 1:
                token = token[:-1]
            if token not in stop_words and len(token) > 1:
                if token in token_frequency:  # if the key exists, increment its frequency
                    token_frequency[token] += 1
                else:  # if the key doesn't exist, add it to the dictionary and update its frequency
                    token_frequency[token] = 1
                if token in page_dict:  # if the key exists, increment its frequency
                    page_dict[token] += 1
                else:  # if the key doesn't exist, add it to the dictionary and update its frequency
                    page_dict[token] = 1
        return page_dict, token_list
    except Exception as e:
        print(e)


def hash_word(word):
    hash_value = 0
    for char in word:
        hash_value += ord(char)

    hash_value %= 65536

    bin_hash = bin(hash_value)[2:].zfill(16)
    return bin_hash


def checksum(tokens):
    """
    Calculate the checksum of each page
    """
    sum = 0
    for token in tokens:
        for char in token:
            sum += ord(char)
    return sum


def simhash(page_dict: dict):
    """
    Detect similar documents. page_dict is every single word on a page with its frequency.
    """
    # Hash each word in the page_dict
    word_hashes = {word: hash_word(word) for word in page_dict.keys()}
    # Initialize fingerprint with 16 bits set to 0
    fingerprint = [0] * 16   

    # Combine hashes using XOR
    for word, hash_value in word_hashes.items():
        for i in range(16):  # Iterate over each bit position
            # Extract i-th bit from the hash value
            bit = (int(hash_value) // (2 ** i)) % 2
            # Update fingerprint using XOR
            fingerprint[i] ^= bit * page_dict[word]

    # Convert fingerprint to binary string
    fingerprint_str = ''.join(map(str, fingerprint))

    return fingerprint_str


 