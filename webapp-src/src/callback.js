/**
 * 
 * Glewlwyd login application
 * 
 * Web application for users to login to Glewlwyd
 * Handle password and schemes authentication
 * 
 * Copyright 2019 Nicolas Mora <mail@babelouest.org>
 * 
 */

import React from 'react';
import ReactDOM from 'react-dom';
import i18next from 'i18next';
import Backend from 'i18next-xhr-backend';
import LanguageDetector from 'i18next-browser-languagedetector';

import apiManager from './lib/APIManager';
import App from './Callback/App';

function getUrlParams(search) {
  if (search) {
      const hashes = search.split('&');
      const params = {};
      hashes.map(hash => {
          const [key, val] = hash.split('=');
          params[key] = decodeURIComponent(val);
      })
      return params;
  } else {
    return {};
  }
}

var initApp = () => {
  apiManager.request("config.json")
  .then((frontEndConfig) => {
    if (!frontEndConfig.lang) {
      frontEndConfig.lang = ["en","fr","nl"];
    }
    apiManager.request(frontEndConfig.GlewlwydUrl + "config/")
    .then((serverConfig) => {
      apiManager.setConfig(frontEndConfig.GlewlwydUrl + serverConfig.api_prefix);
      var config = Object.assign({
        params: {
          state: getUrlParams(window.location.href.split('?')[1]).state||getUrlParams(window.location.hash.substring(1)).state||false
        }
      }, frontEndConfig, serverConfig);
      ReactDOM.render(<App config={config}/>, document.getElementById('root'));
    })
    .fail((error) => {
      ReactDOM.render(<App config={false}/>, document.getElementById('root'));
    });
  });
}

var i18nextOpt = {
  fallbackLng: 'en',
  ns: ['translations'],
  defaultNS: 'translations',
  backend: {
    loadPath: 'locales/{{lng}}/{{ns}}.json'
  }
};

if (getUrlParams(window.location.href.split('?')[1]).ui_locales) {
  i18nextOpt.lng = getUrlParams(window.location.href.split('?')[1]).ui_locales.split(" ")[0];
}

try {
  i18next
  .use(Backend)
  .use(LanguageDetector)
  .init(i18nextOpt)
  .then(() => {
    initApp();
  });
} catch (e) {
  $("#root").html('<div class="alert alert-danger" role="alert">' +
                    '<i class="fas fa-exclamation-triangle"></i>' +
                    '<span class="btn-icon-right">You must use a browser compatible with Glewlwyd SSO</span>' +
                  '</div>');
}
