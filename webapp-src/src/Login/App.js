import React, { Component } from 'react';

import Buttons from './Buttons';
import Body from './Body';

class App extends Component {
	render() {
		return (
      <div className="card center" id="userCard" tabIndex="-1" role="dialog" style={{marginTop: 20 + 'px'}}>
        <div className="card-header">
          <h2>Glewlwyd Single Sign-On</h2>
        </div>
        <div className="card-body">
          <Body/>
        </div>
        <div className="card-footer">
          <Buttons/>
        </div>
      </div>
		);
	}
}

export default App;
