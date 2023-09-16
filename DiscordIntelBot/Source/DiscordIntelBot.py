import json
import os
import requests
import time
from enum import Enum

import signal
import sys
import atexit

import feedparser
from configparser import ConfigParser, NoOptionError
from discord import Webhook, RequestsWebhookAdapter

from Formatting import format_single_article

# expects the configuration file in the same directory as this script by default, replace if desired otherwise
configuration_file_path = os.path.join(
    os.path.split(os.path.abspath(__file__))[0], "/app/Config/Config.txt"
)

# put the discord hook urls to the channels you want to receive feeds in here
with open('/run/secrets/privsec-feed', 'r') as f:
        private_sector_feed = Webhook.from_url(f.read().strip(), adapter=RequestsWebhookAdapter())

with open('/run/secrets/govt-feed', 'r') as f:
        government_feed = Webhook.from_url(f.read().strip(), adapter=RequestsWebhookAdapter())

with open('/run/secrets/ransomware-feed', 'r') as f:
        ransomware_feed = Webhook.from_url(f.read().strip(), adapter=RequestsWebhookAdapter())

with open('/run/secrets/anssi-feed', 'r') as f:
        anssi_feed = Webhook.from_url(f.read().strip(), adapter=RequestsWebhookAdapter())

with open('/run/secrets/rt-feed', 'r') as f:
        rt_feed  = Webhook.from_url(f.read().strip(), adapter=RequestsWebhookAdapter())

with open('/run/secrets/priv_status-feed', 'r') as f:
        status_messages = Webhook.from_url(f.read().strip(), adapter=RequestsWebhookAdapter())

with open('/run/secrets/priv_privsec-feed', 'r') as f:
        priv_private_sector_feed = Webhook.from_url(f.read().strip(), adapter=RequestsWebhookAdapter())

with open('/run/secrets/priv_govt-feed', 'r') as f:
        priv_government_feed = Webhook.from_url(f.read().strip(), adapter=RequestsWebhookAdapter())

with open('/run/secrets/priv_ransomware-feed', 'r') as f:
        priv_ransomware_feed = Webhook.from_url(f.read().strip(), adapter=RequestsWebhookAdapter())

with open('/run/secrets/priv_anssi-feed', 'r') as f:
        priv_anssi_feed = Webhook.from_url(f.read().strip(), adapter=RequestsWebhookAdapter())

with open('/run/secrets/priv_rt-feed', 'r') as f:
        priv_rt_feed = Webhook.from_url(f.read().strip(), adapter=RequestsWebhookAdapter())

#with open('/run/secrets/priv_status-feed', 'r') as f:
#        priv_status_messages = Webhook.from_url(f.read().strip(), adapter=RequestsWebhookAdapter())


private_rss_feed_list = [
    ['https://team-cymru.com/feed/', 'Team Cymru'],
    ['https://feeds.feedburner.com/feedburner/Talos', 'Cisco Talos'],
    ['https://www.cybereason.com/blog/rss.xml', 'CybeReason'],
    ['https://www.crowdstrike.com/blog/feed', 'Crowdstrike'],
    ['https://www.microsoft.com/security/blog/tag/microsoft-security-intelligence/feed/', 'MSTIC'],
    ['https://securelist.com/feed/', 'Securelist'],
    ['https://stairwell.com/feed/atom/', 'Stairwell'],
    ['https://any.run/cybersecurity-blog/feed/', 'Any Run'],
    ['https://www.recordedfuture.com/feed', 'Recorded Future'],
    ['https://decoded.avast.io/feed/', 'Decoded by Avast'],
    #['https://www.mandiant.com/resources/blog/rss.xml', 'Mandiant'],
    ['https://threatpost.com/feed/', 'Threatpost'],
    ['https://krebsonsecurity.com/feed/', 'Krebs on Security'],
    ['http://feeds.feedburner.com/eset/blog', 'We Live Security'],
    ['https://blog.google/threat-analysis-group/rss/', 'Google TAG'],
    ['http://feeds.trendmicro.com/TrendMicroResearch', 'Trend Micro'],
    ['https://www.bleepingcomputer.com/feed/', 'Bleeping Computer'],
    ['https://www.proofpoint.com/us/rss.xml', 'Proof Point'],
    ['https://therecord.media/feed', 'The Record'],
    ['https://www.binarydefense.com/feed/', 'Binary Defense'],
    ['https://securelist.com/feed/', 'Securelist'],
    ['https://research.checkpoint.com/feed/', 'Checkpoint Research'],
    ['https://www.virusbulletin.com/rss', 'VirusBulletin'],
    ['https://blog.xpnsec.com/rss.xml', 'Adam Chester'],
    ['https://msrc-blog.microsoft.com/feed/', 'Microsoft Security'],
    ['https://www.sentinelone.com/feed/', 'SentinelOne'],
    ['https://redcanary.com/feed/', 'RedCanary'],
    ['https://cybersecurity.att.com/site/blog-all-rss', 'ATT'],
	['https://research.nccgroup.com/category/threat-intelligence/feed/', 'NCC Group'],
	['https://isc.sans.edu/rssfeed.xml', 'SANS ISC'],
	['https://unit42.paloaltonetworks.com/feed/', 'Unit 42'],
    ['https://blog.rapid7.com/rss/', 'Rapid7'],
    ['https://blog.virustotal.com/feeds/posts/default', 'Virus Total'],
    ['https://www.greynoise.io/blog/rss.xml', 'Greynoise'],
	['https://www.cyber-news.fr/feeds/local.xml?sort=New', 'Cyber News']
]

gov_rss_feed_list = [
    ["https://www.cisa.gov/uscert/ncas/alerts.xml", "US-CERT CISA"],
    ["https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml", "NCSC"],
    ["https://www.cisecurity.org/feed/advisories", "Center of Internet Security"],
    ['https://cert.ssi.gouv.fr/cti/feed/', 'CERT-FR menaces et incidents'],
    ['https://cert.ssi.gouv.fr/actualite/feed/', 'CERT-FR actualites'],
    ['https://cert.ssi.gouv.fr/alerte/feed/', 'CERT-FR alertes']
]

anssi_rss_feed_list = [
    ['https://cert.ssi.gouv.fr/feed/', 'CERT-FR']
]

rt_rss_feed_list = [
    ['https://www.trustedsec.com/feed/', 'TrustedSec'],
    ['https://s3cur3th1ssh1t.github.io/feed.xml', 'S3cur3Th1sSh1t'],
    ['https://www.blackhillsinfosec.com/feed/', 'Black Hills Infosec'],
    ['https://googleprojectzero.blogspot.com/feeds/posts/default', 'Google Project Zero'],
    ['https://modexp.wordpress.com/feed/', 'Modexp'],
    ['https://www.tiraniddo.dev/feeds/posts/default', 'James Forshaw'],
    ['http://www.harmj0y.net/blog/feed/', 'harmj0y'],
    ['https://dirkjanm.io/feed.xml', 'dirkjanm'],
    ['https://bohops.com/feed/', 'bohops'],
    ['https://g-laurent.blogspot.com/feeds/posts/default', 'Laurent Gaffié'],
    ['https://rastamouse.me/', 'RastaMouse'],
    ['https://wald0.com/?feed=rss2', 'wald0'],
    ['https://posts.specterops.io/feed', 'SpecterOps']
]

FeedTypes = Enum("FeedTypes", "RSS JSON")

source_details = {
    "Private RSS Feed": {
        "source": private_rss_feed_list,
        "hook": [private_sector_feed, priv_private_sector_feed],
        "type": FeedTypes.RSS,
    },
    "Govt RSS Feed": {
        "source": gov_rss_feed_list,
        "hook": [government_feed, priv_government_feed],
        "type": FeedTypes.RSS,
    },
    "Flux RSS ANSSI": {
        "source": anssi_rss_feed_list,
        "hook": [anssi_feed, priv_anssi_feed],
        "type": FeedTypes.RSS,
    },
    "Ransomware News": {
        "source": "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json",
        "hook": [ransomware_feed, priv_ransomware_feed],
        "type": FeedTypes.JSON,
    },
    "Red Team RSS Feed": {
        "source": rt_rss_feed_list,
        "hook": [rt_feed, priv_rt_feed],
        "type": FeedTypes.RSS,
    },
#    "Priv Private RSS Feed": {
#        "source": private_rss_feed_list,
#        "hook": priv_private_sector_feed,
#        "type": FeedTypes.RSS,
#    },
#    "Priv Govt RSS Feed": {
#        "source": gov_rss_feed_list,
#        "hook": priv_government_feed,
#        "type": FeedTypes.RSS,
#    },
#    "Priv ANSSI RSS Feed": {
#        "source": anssi_rss_feed_list,
#        "hook": priv_anssi_feed,
#        "type": FeedTypes.RSS,
#    },
#    "Priv Ransomware RSS Feed": {
#        "source": "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json",
#        "hook": priv_ransomware_feed,
#        "type": FeedTypes.JSON,
#    },
#    "Priv Red Team RSS Feed": {
#        "source": rt_rss_feed_list,
#        "hook": priv_rt_feed,
#        "type": FeedTypes.RSS,
#    },
}


config_file = ConfigParser()
config_file.read(configuration_file_path)


def get_ransomware_news(source):
    posts = requests.get(source).json()

    for post in posts:
        post["publish_date"] = post["discovered"]
        post["title"] = "Post: " + post["post_title"]
        post["source"] = post["group_name"]

    return posts


def get_news_from_rss(rss_item):
    feed_entries = feedparser.parse(rss_item[0]).entries

    # This is needed to ensure that the oldest articles are proccessed first. See https://github.com/vxunderground/ThreatIntelligenceDiscordBot/issues/9 for reference
    for rss_object in feed_entries:
        rss_object["source"] = rss_item[1]
        try:
            rss_object["publish_date"] = time.strftime(
                "%Y-%m-%dT%H:%M:%S", rss_object.published_parsed
            )
        except:
            rss_object["publish_date"] = time.strftime(
                "%Y-%m-%dT%H:%M:%S", rss_object.updated_parsed
            )

    return feed_entries


def proccess_articles(articles):
    messages, new_articles = [], []
    articles.sort(key=lambda article: article["publish_date"])

    for article in articles:
        try:
            config_entry = config_file.get("main", article["source"])
        except NoOptionError:  # automatically add newly discovered groups to config
            config_file.set("main", article["source"], " = ?")
            config_entry = config_file.get("main", article["source"])

        if config_entry.endswith("?"):
            config_file.set("main", article["source"], article["publish_date"])
        else:
            if config_entry >= article["publish_date"]:
                continue

        messages.append(format_single_article(article))
        new_articles.append(article)

    return messages, new_articles


#def send_messages(hook, messages, articles, batch_size=10):
#    for i in range(0, len(messages), batch_size):
#        hook.send(embeds=messages[i : i + batch_size])
#
#        for article in articles[i : i + batch_size]:
#            config_file.set(
#                "main", article["source"], article["publish_date"]
#            )
#
#        time.sleep(3)

def send_messages(webhooks, messages, articles, batch_size=10):
    for i in range(0, len(messages), batch_size):
        for webhook in webhooks:
            webhook.send(embeds=messages[i : i + batch_size])

        for article in articles[i : i + batch_size]:
            for webhook in webhooks:
                config_file.set(
                    "main", article["source"], article["publish_date"]
                )

        time.sleep(3)


def process_source(post_gathering_func, source, hook):
    raw_articles = post_gathering_func(source)

    processed_articles, new_raw_articles = proccess_articles(raw_articles)
    send_messages(hook, processed_articles, new_raw_articles)


def handle_rss_feed_list(rss_feed_list, hook):
    for rss_feed in rss_feed_list:
        status_messages.send(f"> {rss_feed[1]}")
        process_source(get_news_from_rss, rss_feed, hook)


def write_status_messages_to_discord(message):
    status_messages.send(f"**{time.ctime()}**: *{message}*")
    time.sleep(3)


@atexit.register
def clean_up_and_close():
    with open(configuration_file_path, "w") as f:
        config_file.write(f)

    sys.exit(0)


#def main():
#    while True:
#        for detail_name, details in source_details.items():
#            write_status_messages_to_discord(f"Checking {detail_name}")
#
#            if details["type"] == FeedTypes.JSON:
#                process_source(get_ransomware_news, details["source"], details["hook"])
#            elif details["type"] == FeedTypes.RSS:
#                handle_rss_feed_list(details["source"], details["hook"])
#
#        write_status_messages_to_discord("All done")
#        with open(configuration_file_path, "w") as f:
#            config_file.write(f)
#
#        time.sleep(1800)

def main():
    while True:
        for detail_name, details in source_details.items():
            write_status_messages_to_discord(f"Checking {detail_name}")

            if details["type"] == FeedTypes.JSON:
                process_source(get_ransomware_news, details["source"], details["hook"])
            elif details["type"] == FeedTypes.RSS:
                if isinstance(details["hook"], list):  # Check if multiple webhooks
                    handle_rss_feed_list(details["source"], details["hook"])
                else:
                    handle_rss_feed_list([details["source"]], [details["hook"]])

        write_status_messages_to_discord("All done")
        with open(configuration_file_path, "w") as f:
            config_file.write(f)

        time.sleep(1800)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda num, frame: clean_up_and_close())
    main()
