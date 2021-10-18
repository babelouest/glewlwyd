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
import Backend from 'i18next-http-backend';
import LanguageDetector from 'i18next-browser-languagedetector';

import apiManager from './lib/APIManager';
import App from './Login/App';
import ErrorConfig from './lib/ErrorConfig';

const urlParams = new URLSearchParams(window.location.search);

var initApp = () => {
  apiManager.request("config.json")
  .then((frontEndConfig) => {
    if (!frontEndConfig.lang) {
      frontEndConfig.lang = ["en","fr","nl","de"];
    }
    apiManager.request(frontEndConfig.GlewlwydUrl + "config/")
    .then((serverConfig) => {
      apiManager.setConfig(frontEndConfig.GlewlwydUrl + serverConfig.api_prefix);
      apiManager.setConfigSub(frontEndConfig.GlewlwydUrl + serverConfig.api_prefix);
      var config = Object.assign({
        params: {
          scope: urlParams.get("scope")||false, 
          client_id: urlParams.get("client_id")||false, 
          callback_url: urlParams.get("callback_url")||false,
          scheme: urlParams.get("scheme")||frontEndConfig.defaultScheme||false,
          prompt: urlParams.get("prompt")||false,
          refresh_login: !!urlParams.get("refresh_login"),
          login_hint: urlParams.get("login_hint")||false,
          authorization_details: urlParams.get("authorization_details")||false,
          plugin: urlParams.get("plugin")||false,
          ciba_message: urlParams.get("ciba_message")||false,
          ciba_binding_message: urlParams.get("ciba_binding_message")||false,
          ciba_login_hint: urlParams.get("ciba_login_hint")||false
        }
      }, frontEndConfig, serverConfig);
      ReactDOM.render(<App config={config}/>, document.getElementById('root'));
    })
    .fail((error) => {
      ReactDOM.render(<App config={false}/>, document.getElementById('root'));
    });
  })
  .fail((error) => {
    ReactDOM.render(<ErrorConfig/>, document.getElementById('root'));
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

if (urlParams.get("ui_locales")) {
  i18nextOpt.lng = urlParams.get("ui_locales").split(" ")[0];
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
