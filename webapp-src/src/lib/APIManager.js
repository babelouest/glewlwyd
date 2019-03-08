class APIManager {
	constructor() {
	}
	
	APIRequest(method, url, data) {
		return $.ajax({
			method: method,
			url: url,
			data: JSON.stringify(data),
			contentType: data?"application/json; charset=utf-8":null
		});
	}
	
}

export default APIManager;
