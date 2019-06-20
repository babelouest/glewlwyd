import React from 'react';
import ReactDOM from 'react-dom';
import Backend from '../js/i18nextXHRBackend';
import LanguageDetector from '../js/i18nextBrowserLanguageDetector';

import apiManager from './lib/APIManager';
import App from './Login/App';

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
      var config = Object.assign({
        params: {
          scope: getParameterByName("scope"), 
          client_id: getParameterByName("client_id"), 
          callback_url: getParameterByName("callback_url")
        }
      }, frontEndConfig, serverConfig);
      var scheme = getParameterByName("scheme")||false;
      ReactDOM.render(<App config={config} scheme={scheme}/>, document.getElementById('root'));
    })
    .fail((error) => {
      ReactDOM.render(<App config={false} scheme={false}/>, document.getElementById('root'));
    });
  });
}

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
