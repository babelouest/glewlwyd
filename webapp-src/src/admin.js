import React from 'react';
import ReactDOM from 'react-dom';
import Backend from '../js/i18nextXHRBackend';
import LanguageDetector from '../js/i18nextBrowserLanguageDetector';

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
