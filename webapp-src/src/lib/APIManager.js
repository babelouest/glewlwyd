import messageDispatcher from '../lib/MessageDispatcher';

class APIManager {
  constructor() {
    this.GlewlwydApiPrefix = "";
    this.GlewlwydApiPrefixSub = "";
  }

  setConfig(GlewlwydApiPrefix) {
    this.GlewlwydApiPrefix = GlewlwydApiPrefix;
  }
  
  getConfig(GlewlwydApiPrefix) {
    return this.GlewlwydApiPrefix;
  }

  setConfigSub(GlewlwydApiPrefix) {
    this.GlewlwydApiPrefixSub = GlewlwydApiPrefix;
  }
  
  getConfigSub(GlewlwydApiPrefix) {
    return this.GlewlwydApiPrefixSub;
  }

  request(url, method="GET", data=false) {
    if (data && method !== "GET") {
      return $.ajax({
        method: method,
        url: url,
        data: JSON.stringify(data),
        contentType: "application/json; charset=utf-8"
      });
    } else {
      return $.ajax({
        method: method,
        url: url
      });
    }
  }

  glewlwydRequest(url, method="GET", data=false, unsafe=false) {
    return this.request(this.GlewlwydApiPrefix + url, method, data)
    .fail((err) => {
      if (unsafe && err.status === 401) {
        messageDispatcher.sendMessage('App', {type: "loggedIn", message: false});
      }
    });
  }

  glewlwydRequestSub(url, method="GET", data=false) {
    return this.request(this.GlewlwydApiPrefixSub + url, method, data);
  }
}

let apiManager = new APIManager();

export default apiManager;
