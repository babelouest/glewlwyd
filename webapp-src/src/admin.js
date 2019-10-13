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
import Backend from 'i18next-xhr-backend';
import LanguageDetector from 'i18next-browser-languagedetector';

import apiManager from './lib/APIManager';
import App from './Admin/App';

var getParameterByName = function (name, url) {
  if (!url) url = window.location.href;
  name = name.replace(/[\[\]]/g, '\\$&');
  var regex = new RegExp('[?&]' + name + '(=([^&#]*)|&|#|$)'), results = regex.exec(url);
  if (!results)
    return null;
  if (!results[2])
    return '';
  return decodeURIComponent(results[2].replace(/\+/g, ' '));
};

var initApp = () => {
  apiManager.request("config.json")
  .then((frontEndConfig) => {
    apiManager.request(frontEndConfig.GlewlwydUrl + "config/")
    .then((serverConfig) => {
      apiManager.setConfig(frontEndConfig.GlewlwydUrl + serverConfig.api_prefix);
      var config = Object.assign({params: {scope: getParameterByName("scope"), client_id: getParameterByName("client_id"), callback_url: getParameterByName("callback_url")}}, frontEndConfig, serverConfig);
      ReactDOM.render(<App config={config} />, document.getElementById('root'));
    })
    .fail((error) => {
      ReactDOM.render(<App config={false} />, document.getElementById('root'));
    });
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
    initApp()
  });
} catch (e) {
  $("#root").html('<div class="alert alert-danger" role="alert">' +
                    '<i class="fas fa-exclamation-triangle"></i>' +
                    '<span class="btn-icon-right">You must use a browser compatible with Glewlwyd SSO</span>' +
                  '</div>');
}
