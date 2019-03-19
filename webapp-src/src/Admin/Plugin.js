import React, { Component } from 'react';

import messageDispatcher from '../lib/MessageDispatcher';

class Plugin extends Component {
  constructor(props) {
    super(props);

    this.state = {
    }

    messageDispatcher.subscribe('Plugins', (message) => {
    });
  }
  
	render() {
		return (
"Plugins"
		);
	}
}

export default Plugin;
