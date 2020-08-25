/**
 * 
 * Glewlwyd profile application
 * 
 * Web application for users to manage their profile
 * Used to manage personal data and schemes registration
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
import App from './Profile/App';
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
      if (urlParams.get("delegate")) {
        apiManager.setConfig(frontEndConfig.GlewlwydUrl + serverConfig.api_prefix + "/delegate/" + urlParams.get("delegate"));
      } else {
        apiManager.setConfig(frontEndConfig.GlewlwydUrl + serverConfig.api_prefix);
      }
      apiManager.setConfigSub(frontEndConfig.GlewlwydUrl + serverConfig.api_prefix);
      var config = Object.assign({
        params: {
          scope: urlParams.get("scope"), 
          client_id: urlParams.get("client_id"), 
          callback_url: urlParams.get("callback_url"),
          delegate: urlParams.get("delegate")||false,
          register: urlParams.get("register")||false,
          updateEmail: urlParams.get("updateEmail")||false,
          token: urlParams.get("token")||false,
          scheme_name: urlParams.get("scheme_name")||false,
          provider: urlParams.get("provider")||false,
          resetCredentials: urlParams.get("resetCredentials")||false
        }
      }, frontEndConfig, serverConfig);
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
