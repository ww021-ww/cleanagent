from elasticsearch import Elasticsearch
from app.config.settings import ES_HOST

es = Elasticsearch(ES_HOST)
