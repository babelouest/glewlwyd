/**
 * 
 * Glewlwyd admin application
 * 
 * Web application to manage users, clients, scopes, module instances, scheme instances and plugin instances
 * 
 * Copyright 2019 Nicolas Mora <mail@babelouest.org>
 * 
 */

import React from 'react';
import ReactDOM from 'react-dom';
import i18next from 'i18next';
import Backend from 'i18next-http-backend';
import LanguageDetector from 'i18next-browser-languagedetector';

import apiManager from './lib/APIManager';
import App from './Admin/App';
import ErrorConfig from './lib/ErrorConfig';

var initApp = () => {
  const urlParams = new URLSearchParams(window.location.search);
  apiManager.request("config.json")
  .then((frontEndConfig) => {
    if (!frontEndConfig.lang) {
      frontEndConfig.lang = ["en","fr","nl"];
    }
    apiManager.request(frontEndConfig.GlewlwydUrl + "config/")
    .then((serverConfig) => {
      apiManager.setConfig(frontEndConfig.GlewlwydUrl + serverConfig.api_prefix);
      var config = Object.assign(
        {
          params: {
            scope: urlParams.get("scope"), 
            client_id: urlParams.get("client_id"), 
            callback_url: urlParams.get("callback_url")
          }, 
          scopes: []
        }, 
        frontEndConfig, 
        serverConfig);
      ReactDOM.render(<App config={config} />, document.getElementById('root'));
    })
    .fail((error) => {
      ReactDOM.render(<App config={false} />, document.getElementById('root'));
    });
  })
  .fail((error) => {
    ReactDOM.render(<ErrorConfig/>, document.getElementById('root'));
  });
}

try {
  i18next
  .use(Backend)
  .use(LanguageDetector)
  .init({
    fallbackLng: 'en',
    ns: ['translations'],
    defaultNS: 'translations',
    backend: {
      loadPath: 'locales/{{lng}}/{{ns}}.json'
    }
  })
  .then(() => {
    initApp();
  });
} catch (e) {
  $("#root").html('<div class="alert alert-danger" role="alert">' +
                    '<i class="fas fa-exclamation-triangle"></i>' +
                    '<span class="btn-icon-right">You must use a browser compatible with Glewlwyd SSO</span>' +
                  '</div>');
}
