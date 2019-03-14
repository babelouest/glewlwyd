import React, { Component } from 'react';

import messageDispatcher from '../lib/MessageDispatcher';

class UsersMod extends Component {
  constructor(props) {
    super(props);

    this.state = {
    }

    messageDispatcher.subscribe('UsersMod', (message) => {
    });
  }
  
	render() {
		return (
"UsersMod"
		);
	}
}

export default UsersMod;
