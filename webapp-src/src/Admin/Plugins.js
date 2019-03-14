import React, { Component } from 'react';

import messageDispatcher from '../lib/MessageDispatcher';

class Plugins extends Component {
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

export default Plugins;
