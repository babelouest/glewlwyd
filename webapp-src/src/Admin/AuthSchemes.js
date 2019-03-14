import React, { Component } from 'react';

import messageDispatcher from '../lib/MessageDispatcher';

class AuthSchemes extends Component {
  constructor(props) {
    super(props);

    this.state = {
    }

    messageDispatcher.subscribe('AuthSchemes', (message) => {
    });
  }
  
	render() {
		return (
"AuthSchemes"
		);
	}
}

export default AuthSchemes;
