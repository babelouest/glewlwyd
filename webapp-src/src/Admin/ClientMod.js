import React, { Component } from 'react';

import messageDispatcher from '../lib/MessageDispatcher';

class ClientMod extends Component {
  constructor(props) {
    super(props);

    this.state = {
    }

    messageDispatcher.subscribe('ClientsMod', (message) => {
    });
  }
  
	render() {
		return (
"ClientsMod"
		);
	}
}

export default ClientMod;
