import React, { Component } from 'react';

import apiManager from '../lib/APIManager';
import messageDispatcher from '../lib/MessageDispatcher';
import Notification from '../lib/Notification';

class App extends Component {
  constructor(props) {
    super(props);

    messageDispatcher.subscribe('App', (message) => {
    });
  }

	render() {
		return (
      <div>
        <div className="card center" id="userCard" tabIndex="-1" role="dialog" style={{marginTop: 20 + 'px', marginBottom: 20 + 'px'}}>
          <div className="card-header">
            <h2>{i18next.t("glewlwyd-sso-title")}</h2>
          </div>
          <div className="card-body">
          body
          </div>
          <div className="card-footer">
          footer
          </div>
        </div>
        <Notification/>
      </div>
		);
	}
}

export default App;
