import React, { Component } from 'react';

import messageDispatcher from '../lib/MessageDispatcher';

class AuthScheme extends Component {
  constructor(props) {
    super(props);

    this.state = {
    }

    messageDispatcher.subscribe('AuthScheme', (message) => {
    });
  }
  
	render() {
		return (
"AuthScheme"
		);
	}
}

export default AuthScheme;
