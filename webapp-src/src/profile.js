import React from 'react';
import ReactDOM from 'react-dom';

import App from './Profile/App';

function getBestStorageAvailable(storageType) {
	if (storageType === "local") {
		var testVal = "testLocalStorage";
		try {
			localStorage.setItem(testVal, testVal);
			localStorage.removeItem(testVal);
			return storageType;
		} catch (e) {
			return "cookie";
		}
	} else {
		return storageType;
	}
}

ReactDOM.render(<App/>, document.getElementById('root'));
