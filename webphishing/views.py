import imp
from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
import numpy as np
import datetime, os
import joblib
import pickle
import signal
import re
import requests
import urllib.parse
from urllib.parse import urlparse
import tldextract
from datetime import datetime
from bs4 import BeautifulSoup
import whois
import time
import sys
import warnings
from pathlib import Path
import json

import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Activation, Dropout, BatchNormalization
from tensorflow.keras.utils import to_categorical, plot_model


from .scripts import extract_url as eu
from .scripts import content_features as cf
from .scripts import external_features as ef
from .scripts import url_features as uf


class NpEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, np.integer):
            return int(obj)
        if isinstance(obj, np.floating):
            return float(obj)
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        return super(NpEncoder, self).default(obj)

def index(request):
    return render(request, 'home.html')


def result(request):
    if request.method == 'POST':
        urlweb = request.POST["url"]
        api_key = "c0sc88cccogs8g4c0c8osgowskg44ogs8ow4wk8w" # One Page Rank API
        state, url, page = eu.is_URL_accessible(urlweb)
        Href = {'internals':[], 'externals':[], 'null':[]}
        Link = {'internals':[], 'externals':[], 'null':[]}
        Anchor = {'safe':[], 'unsafe':[], 'null':[]}
        Media = {'internals':[], 'externals':[], 'null':[]}
        Form = {'internals':[], 'externals':[], 'null':[]}
        CSS = {'internals':[], 'externals':[], 'null':[]}
        Favicon = {'internals':[], 'externals':[], 'null':[]}
        IFrame = {'visible':[], 'invisible':[], 'null':[]}
        Title =''
        Text= ''

        if state:
            content = page.content
            hostname, domain, path = eu.get_domain(url)
            extracted_domain = tldextract.extract(url)
            domain = extracted_domain.domain +'.'+ extracted_domain.suffix
            subdomain = extracted_domain.subdomain
            tmp = url[url.find(extracted_domain.suffix):len(url)]
            pth = tmp.partition("/")
            path = pth[1] + pth[2]
            words_raw, words_raw_host, words_raw_path= eu.words_raw_extraction(extracted_domain.domain, subdomain, pth[2])
            tld = extracted_domain.suffix
            parsed = urlparse(url)
            scheme = parsed.scheme
            Href, Link, Anchor, Media, Form, CSS, Favicon, IFrame, Title, Text = eu.extract_data_from_URL(hostname, content, domain, Href, Link, Anchor, Media, Form, CSS, Favicon, IFrame, Title, Text)
        else:
            return render(request, '404notfound.html', context={"url": urlweb})
        
        google_index = ef.google_index(url)
        page_rank = ef.page_rank(api_key, domain)
        nb_www = uf.check_www(words_raw)
        ratio_digits_url = uf.ratio_digits(url)
        domain_in_title = cf.domain_in_title(extracted_domain.domain, Title)
        nb_hyperlinks = cf.nb_hyperlinks(Href, Link, Media, Form, CSS, Favicon)
        phish_hints = uf.phish_hints(url)
        domain_age = ef.count_domain_age(domain)
        ip = uf.having_ip_address(url)
        nb_qm = uf.count_exclamation(url)
        ratio_intHyperlinks = cf.internal_hyperlinks(Href, Link, Media, Form, CSS, Favicon)
        length_url = uf.url_length(url)
        nb_slash = uf.count_slash(url)
        length_hostname = uf.url_length(hostname)
        nb_eq = uf.count_equal(url)
        shortest_word_host = uf.shortest_word_length(words_raw_host)
        longest_word_path = uf.longest_word_length(words_raw_path)
        ratio_digits_host = uf.ratio_digits(hostname)
        prefix_suffix = uf.prefix_suffix(url)
        nb_dots = uf.count_dots(url)
        empty_title = cf.empty_title(Title)
        longest_words_raw = uf.longest_word_length(words_raw)
        tld_in_subdomain = uf.tld_in_subdomain(tld, subdomain)
        length_words_raw = uf.length_word_raw(words_raw)
        ratio_intMedia = cf.internal_media(Media)
        avg_word_path = uf.average_word_length(words_raw_path)
        avg_word_host = uf.average_word_length(words_raw_host)

        # data_input = [google_index, page_rank, nb_www, ratio_digits_url, domain_in_title, nb_hyperlinks, phish_hints, domain_age, ip, nb_qm, ratio_intHyperlinks, length_url, nb_slash, length_hostname, nb_eq, shortest_word_host, longest_word_path, ratio_digits_host, prefix_suffix, nb_dots, empty_title, longest_words_raw, tld_in_subdomain, length_words_raw, ratio_intMedia]
        
        data_input = [google_index, page_rank, nb_www, ratio_digits_url, domain_in_title, domain_age, nb_hyperlinks, phish_hints, ip, nb_qm, length_url, ratio_intHyperlinks, nb_slash, nb_eq, length_hostname,shortest_word_host, ratio_digits_host, empty_title, prefix_suffix,nb_dots,longest_word_path,avg_word_path,avg_word_host,tld_in_subdomain,longest_words_raw]

        path = str(Path(__file__).resolve().parent.parent)
        scaler_load = joblib.load(path + '/webphishing/scripts/std_scaler.bin')
        load_model = tf.keras.models.load_model(path + '/webphishing/scripts/mlp_model_fs_25.h5')
        data_scale = scaler_load.transform([data_input])
        load_model.compile(loss=[tf.keras.losses.CategoricalCrossentropy(), tf.keras.losses.MeanSquaredError()], 
                optimizer=tf.keras.optimizers.Adam(learning_rate=0.0001), 
                metrics=['accuracy', tf.keras.metrics.MeanSquaredError()])
        result = load_model.predict([data_scale])
        result = np.argmax(result, axis = 1)

        # return JsonResponse({"data_input": data_input, "data_scale": json.dumps(data_scale[0], cls=NpEncoder), "result": json.dumps(result[0], cls=NpEncoder)})

        return render(request, 'result.html', context={"url": url, "data_input":data_input, "data_scale": data_scale[0], "result":result})

def notfound(request):
    return render(request, '404notfound.html')