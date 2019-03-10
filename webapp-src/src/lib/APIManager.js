class APIManager {
	constructor() {
    this.GlewlwydApiPrefix = "";
	}

  setConfig(GlewlwydApiPrefix) {
    this.GlewlwydApiPrefix = GlewlwydApiPrefix;
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

  glewlwydRequest(url, method="GET", data=false) {
    return this.request(this.GlewlwydApiPrefix + url, method, data);
  }
	
}

let apiManager = new APIManager();

export default apiManager;
